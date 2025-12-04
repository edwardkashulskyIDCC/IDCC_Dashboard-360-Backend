const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const { sendEmailRawSMTP } = require('./email-service');

const app = express();
app.use(cors());
app.use(express.json());

// Database configuration - can use shared DB or separate
const DB_PATH = process.env.EMAIL_DB_PATH || path.join(__dirname, 'scheduled-emails.db');

// Initialize database
let db;
try {
  db = new Database(DB_PATH);
  console.log('📦 Email Server: Connected to scheduled emails database');
} catch (error) {
  console.error('❌ Email Server: Failed to connect to database:', error);
  process.exit(1);
}

// Ensure tables exist
db.exec(`
  CREATE TABLE IF NOT EXISTS scheduled_emails (
    id TEXT PRIMARY KEY,
    to_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    text_body TEXT NOT NULL,
    html_body TEXT,
    ics_content TEXT,
    scheduled_for TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    created_at TEXT NOT NULL,
    sent_at TEXT,
    failed_at TEXT,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3
  );
  
  CREATE INDEX IF NOT EXISTS idx_scheduled_for ON scheduled_emails(scheduled_for);
  CREATE INDEX IF NOT EXISTS idx_status ON scheduled_emails(status);
  
  CREATE TABLE IF NOT EXISTS email_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    error_message TEXT,
    FOREIGN KEY (email_id) REFERENCES scheduled_emails(id)
  );
`);

// Prepared statements
const stmts = {
  insert: db.prepare(`
    INSERT INTO scheduled_emails 
    (id, to_email, subject, text_body, html_body, ics_content, scheduled_for, created_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scheduled')
  `),
  
  updateStatus: db.prepare(`
    UPDATE scheduled_emails 
    SET status = ?, sent_at = ?, failed_at = ?, error_message = ?, retry_count = ?
    WHERE id = ?
  `),
  
  getPending: db.prepare(`
    SELECT * FROM scheduled_emails 
    WHERE status = 'scheduled' AND scheduled_for <= ?
    ORDER BY scheduled_for ASC
    LIMIT ?
  `),
  
  getById: db.prepare('SELECT * FROM scheduled_emails WHERE id = ?'),
  
  cancel: db.prepare(`UPDATE scheduled_emails SET status = 'cancelled' WHERE id = ?`),
  
  getAll: db.prepare(`
    SELECT * FROM scheduled_emails 
    ORDER BY scheduled_for DESC 
    LIMIT ?
  `),
  
  cleanup: db.prepare(`
    DELETE FROM scheduled_emails 
    WHERE status IN ('sent', 'cancelled', 'expired') 
    AND created_at < datetime('now', '-30 days')
  `),
  
  addHistory: db.prepare(`
    INSERT INTO email_history (email_id, status, timestamp, error_message)
    VALUES (?, ?, ?, ?)
  `)
};

/**
 * Send a scheduled email
 */
async function sendScheduledEmail(emailId) {
  const email = stmts.getById.get(emailId);
  
  if (!email) {
    console.error(`❌ Scheduled email not found: ${emailId}`);
    return { success: false, error: 'Email not found' };
  }
  
  if (email.status !== 'scheduled') {
    console.log(`⚠️ Email ${emailId} status is ${email.status}, skipping`);
    return { success: false, error: `Email status is ${email.status}` };
  }
  
  try {
    console.log(`📧 Sending scheduled email: ${emailId} to ${email.to_email}`);
    
    const emailData = {
      to: email.to_email,
      subject: email.subject,
      text: email.text_body,
      html: email.html_body || undefined,
      icsContent: email.ics_content || undefined
    };
    
    await sendEmailRawSMTP(emailData);
    
    // Update status to sent
    stmts.updateStatus.run('sent', new Date().toISOString(), null, null, email.retry_count, emailId);
    stmts.addHistory.run(emailId, 'sent', new Date().toISOString(), null);
    
    console.log(`✅ Scheduled email sent successfully: ${emailId}`);
    return { success: true, emailId, status: 'sent' };
  } catch (error) {
    console.error(`❌ Failed to send scheduled email ${emailId}:`, error);
    
    const retryCount = (email.retry_count || 0) + 1;
    const maxRetries = email.max_retries || 3;
    
    if (retryCount < maxRetries) {
      // Schedule retry (exponential backoff: 5min, 15min, 45min)
      const retryDelay = Math.min(5 * Math.pow(3, retryCount - 1) * 60 * 1000, 60 * 60 * 1000);
      const retryTime = new Date(Date.now() + retryDelay);
      
      console.log(`🔄 Scheduling retry ${retryCount}/${maxRetries} for ${emailId} in ${Math.round(retryDelay / 1000 / 60)} minutes`);
      
      // Update scheduled_for for retry
      db.prepare('UPDATE scheduled_emails SET scheduled_for = ?, retry_count = ? WHERE id = ?').run(
        retryTime.toISOString(),
        retryCount,
        emailId
      );
      
      stmts.addHistory.run(emailId, 'retry', new Date().toISOString(), `Retry ${retryCount}/${maxRetries}`);
      
      return { success: false, error: error.message, retryScheduled: true, retryCount };
    } else {
      // Max retries reached, mark as failed
      stmts.updateStatus.run(
        'failed',
        null,
        new Date().toISOString(),
        error.message,
        retryCount,
        emailId
      );
      stmts.addHistory.run(emailId, 'failed', new Date().toISOString(), error.message);
      
      return { success: false, error: error.message, maxRetriesReached: true };
    }
  }
}

/**
 * Process pending emails
 */
function processPendingEmails() {
  try {
    const now = new Date().toISOString();
    const pending = stmts.getPending.all(now, 50); // Process up to 50 at a time
    
    if (pending.length > 0) {
      console.log(`📬 Processing ${pending.length} pending emails...`);
      
      // Send emails concurrently (but limit concurrency)
      const sendPromises = pending.slice(0, 10).map(email => sendScheduledEmail(email.id));
      
      Promise.allSettled(sendPromises).then(results => {
        const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        const failed = results.filter(r => r.status === 'rejected' || !r.value?.success).length;
        console.log(`✅ Processed: ${successful} sent, ${failed} failed`);
      });
    }
  } catch (error) {
    console.error('❌ Error processing pending emails:', error);
  }
}

// ========================================
// API ENDPOINTS
// ========================================

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'email-server',
    timestamp: new Date().toISOString(),
    pendingEmails: stmts.getPending.all(new Date().toISOString(), 1000).length
  });
});

// Get scheduled emails (with pagination)
app.get('/api/scheduled-emails', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const status = req.query.status; // optional filter
    
    let query = 'SELECT * FROM scheduled_emails';
    const params = [];
    
    if (status) {
      query += ' WHERE status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY scheduled_for DESC LIMIT ?';
    params.push(limit);
    
    const emails = db.prepare(query).all(...params);
    
    res.json({
      success: true,
      count: emails.length,
      emails: emails
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific email
app.get('/api/scheduled-emails/:id', (req, res) => {
  try {
    const email = stmts.getById.get(req.params.id);
    
    if (!email) {
      return res.status(404).json({ success: false, error: 'Email not found' });
    }
    
    res.json({ success: true, email });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Cancel scheduled email
app.post('/api/scheduled-emails/:id/cancel', (req, res) => {
  try {
    const email = stmts.getById.get(req.params.id);
    
    if (!email) {
      return res.status(404).json({ success: false, error: 'Email not found' });
    }
    
    if (email.status !== 'scheduled') {
      return res.status(400).json({ 
        success: false, 
        error: `Email status is ${email.status}, cannot cancel` 
      });
    }
    
    stmts.cancel.run(req.params.id);
    stmts.addHistory.run(req.params.id, 'cancelled', new Date().toISOString(), null);
    
    console.log(`❌ Cancelled scheduled email: ${req.params.id}`);
    res.json({ success: true, emailId: req.params.id });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Send email immediately (bypass schedule)
app.post('/api/scheduled-emails/:id/send-now', async (req, res) => {
  try {
    const result = await sendScheduledEmail(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Schedule email endpoint (called by main server)
app.post('/api/schedule-email', (req, res) => {
  try {
    const { emailData, scheduledFor } = req.body;
    
    if (!emailData || !emailData.to || !scheduledFor) {
      return res.status(400).json({ 
        success: false, 
        error: 'emailData and scheduledFor are required' 
      });
    }
    
    const scheduleTime = new Date(scheduledFor);
    const now = new Date();
    
    if (scheduleTime <= now) {
      return res.status(400).json({ 
        success: false, 
        error: 'scheduledFor must be in the future' 
      });
    }
    
    // Generate unique ID
    const emailId = `scheduled-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Insert into database
    stmts.insert.run(
      emailId,
      emailData.to,
      emailData.subject,
      emailData.text,
      emailData.html || null,
      emailData.icsContent || null,
      scheduleTime.toISOString(),
      now.toISOString()
    );
    
    console.log(`📅 Email scheduled: ${emailId} for ${scheduleTime.toISOString()}`);
    
    res.json({
      success: true,
      emailId: emailId,
      scheduledFor: scheduleTime.toISOString(),
      delayMinutes: Math.round((scheduleTime.getTime() - now.getTime()) / 1000 / 60)
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Manual trigger to process pending emails
app.post('/api/process-pending', (req, res) => {
  try {
    processPendingEmails();
    res.json({ 
      success: true, 
      message: 'Processing pending emails',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// BACKGROUND PROCESSING
// ========================================

// Process pending emails every 2 minutes
const PROCESS_INTERVAL = 2 * 60 * 1000; // 2 minutes
setInterval(processPendingEmails, PROCESS_INTERVAL);

// Cleanup old emails daily
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
setInterval(() => {
  try {
    const result = stmts.cleanup.run();
    if (result.changes > 0) {
      console.log(`🧹 Cleaned up ${result.changes} old email records`);
    }
  } catch (error) {
    console.error('Error cleaning up old emails:', error);
  }
}, CLEANUP_INTERVAL);

// Process immediately on startup
console.log('🚀 Email Server starting...');
processPendingEmails();

// ========================================
// START SERVER
// ========================================

const PORT = process.env.EMAIL_SERVER_PORT || 4501;

app.listen(PORT, () => {
  console.log(`📧 Email Server listening on port ${PORT}`);
  console.log(`📅 Processing emails every ${PROCESS_INTERVAL / 1000} seconds`);
  console.log(`🧹 Cleanup interval: ${CLEANUP_INTERVAL / 1000 / 60} minutes`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n📧 Email Server shutting down...');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n📧 Email Server shutting down...');
  db.close();
  process.exit(0);
});

