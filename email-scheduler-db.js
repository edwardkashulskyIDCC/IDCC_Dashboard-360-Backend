const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { sendEmailRawSMTP } = require('./email-service');

// Database file path
const DB_PATH = path.join(__dirname, 'scheduled-emails.db');

// Initialize database with WAL mode for concurrent access
let db;
try {
  db = new Database(DB_PATH, {
    timeout: 30000 // Wait up to 30 seconds for locks
  });
  
  // Enable WAL mode for better concurrent access
  try {
    db.pragma('journal_mode = WAL');
    console.log('📦 Connected to scheduled emails database (WAL mode enabled)');
  } catch (walError) {
    console.warn('⚠️ Could not set WAL mode (database may be locked):', walError.message);
    console.log('📦 Connected to scheduled emails database (WAL mode not available)');
  }
  
  // Set busy timeout to wait for locks (30 seconds)
  try {
    db.pragma('busy_timeout = 30000');
  } catch (timeoutError) {
    console.warn('⚠️ Could not set busy timeout:', timeoutError.message);
  }
} catch (error) {
  console.error('❌ Failed to connect to database:', error);
  throw error;
}

// Create tables if they don't exist
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

// Prepared statements for better performance
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

// In-memory map of active timers (for cancellation)
const activeTimers = new Map();

/**
 * Schedule an email to be sent at a future date/time
 * If EMAIL_SERVER_URL is set, sends to email server. Otherwise uses local database.
 * @param {Object} emailData - Email details
 * @param {Date|string} sendDate - When to send the email
 * @returns {Promise<Object>} Scheduled email info
 */
async function scheduleEmail(emailData, sendDate) {
  const now = new Date();
  const scheduleTime = new Date(sendDate);
  
  if (scheduleTime <= now) {
    throw new Error('Send date must be in the future');
  }
  
  // Check if email server is configured
  const emailServerUrl = process.env.EMAIL_SERVER_URL || null;
  
  if (emailServerUrl) {
    // Use separate email server
    try {
      // Use native fetch if available (Node 18+), otherwise node-fetch
      let fetchFn;
      if (global.fetch) {
        fetchFn = global.fetch;
      } else {
        // node-fetch v2 exports function directly, v3 uses default export
        try {
          fetchFn = require('node-fetch');
          // If it has a default property, use that (v3)
          if (fetchFn.default) {
            fetchFn = fetchFn.default;
          }
        } catch (e) {
          throw new Error('Could not load fetch. Please install node-fetch: npm install node-fetch@2');
        }
      }
      
      const response = await fetchFn(`${emailServerUrl}/api/schedule-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          emailData,
          scheduledFor: scheduleTime.toISOString()
        })
      });
      
      if (!response.ok) {
        throw new Error(`Email server error: ${response.statusText}`);
      }
      
      const result = await response.json();
      console.log(`📅 Email scheduled via email server: ${result.emailId}`);
      return result;
    } catch (error) {
      console.error('⚠️ Email server unavailable, falling back to local scheduling:', error.message);
      // Fall through to local scheduling
    }
  }
  
  // Local scheduling (original behavior)
  // Generate unique ID
  const emailId = `scheduled-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  // Use transaction for atomic operation
  const insert = db.transaction((data, id, scheduledFor, createdAt) => {
    stmts.insert.run(
      id,
      data.to,
      data.subject,
      data.text,
      data.html || null,
      data.icsContent || null,
      scheduledFor,
      createdAt
    );
  });
  
  try {
    insert(
      emailData,
      emailId,
      scheduleTime.toISOString(),
      now.toISOString()
    );
    
    // Note: With separate email server, we don't use setTimeout here
    // The email server will handle processing via polling
    console.log(`📅 Email scheduled in database: ${emailId} for ${scheduleTime.toISOString()} (${Math.round((scheduleTime.getTime() - now.getTime()) / 1000 / 60)} minutes from now)`);
    
    return {
      success: true,
      emailId: emailId,
      scheduledFor: scheduleTime.toISOString(),
      delayMinutes: Math.round((scheduleTime.getTime() - now.getTime()) / 1000 / 60)
    };
  } catch (error) {
    console.error(`❌ Error scheduling email:`, error);
    throw error;
  }
}

/**
 * Send a scheduled email
 */
async function sendScheduledEmail(emailId) {
  const email = stmts.getById.get(emailId);
  
  if (!email) {
    console.error(`❌ Scheduled email not found: ${emailId}`);
    return;
  }
  
  if (email.status !== 'scheduled') {
    console.log(`⚠️ Email ${emailId} status is ${email.status}, skipping`);
    return;
  }
  
  try {
    console.log(`📧 Sending scheduled email: ${emailId}`);
    
    const emailData = {
      to: email.to_email,
      subject: email.subject,
      text: email.text_body,
      html: email.html_body || undefined,
      icsContent: email.ics_content || undefined
    };
    
    // Send email - catch errors but check if email was actually sent
    let emailSent = false;
    try {
      await sendEmailRawSMTP(emailData);
      emailSent = true;
    } catch (sendError) {
      // Check if error message suggests email might have been sent anyway
      if (sendError.message && (
        sendError.message.includes('timeout after acceptance') ||
        sendError.message.includes('Email sent (timeout')
      )) {
        console.warn(`⚠️ Email ${emailId} may have been sent despite timeout warning`);
        emailSent = true; // Treat as success
      } else {
        throw sendError; // Re-throw if it's a real error
      }
    }
    
    if (emailSent) {
      // Update status to sent (with retry for locks)
      let updateRetries = 5;
      while (updateRetries > 0) {
        try {
          stmts.updateStatus.run('sent', new Date().toISOString(), null, null, email.retry_count, emailId);
          stmts.addHistory.run(emailId, 'sent', new Date().toISOString(), null);
          break;
        } catch (updateError) {
          const isLocked = updateError.message && (
            updateError.message.includes('locked') || 
            updateError.message.includes('SQLITE_BUSY') ||
            updateError.code === 'SQLITE_BUSY'
          );
          if (isLocked && updateRetries > 1) {
            updateRetries--;
            const sleep = (ms) => {
              const start = Date.now();
              while (Date.now() - start < ms) {}
            };
            sleep(500);
          } else {
            throw updateError;
          }
        }
      }
      
      console.log(`✅ Scheduled email sent successfully: ${emailId}`);
    }
  } catch (error) {
    console.error(`❌ Failed to send scheduled email ${emailId}:`, error);
    
    const retryCount = (email.retry_count || 0) + 1;
    const maxRetries = email.max_retries || 3;
    
    if (retryCount < maxRetries) {
      // Schedule retry (exponential backoff: 5min, 15min, 45min)
      const retryDelay = Math.min(5 * Math.pow(3, retryCount - 1) * 60 * 1000, 60 * 60 * 1000);
      const retryTime = new Date(Date.now() + retryDelay);
      
      console.log(`🔄 Scheduling retry ${retryCount}/${maxRetries} for ${emailId} in ${Math.round(retryDelay / 1000 / 60)} minutes`);
      
      // Update scheduled_for for retry (with retry for locks)
      let retryUpdateRetries = 5;
      while (retryUpdateRetries > 0) {
        try {
          db.prepare('UPDATE scheduled_emails SET scheduled_for = ?, retry_count = ? WHERE id = ?').run(
            retryTime.toISOString(),
            retryCount,
            emailId
          );
          break;
        } catch (retryUpdateError) {
          const isLocked = retryUpdateError.message && (
            retryUpdateError.message.includes('locked') || 
            retryUpdateError.message.includes('SQLITE_BUSY') ||
            retryUpdateError.code === 'SQLITE_BUSY'
          );
          if (isLocked && retryUpdateRetries > 1) {
            retryUpdateRetries--;
            const sleep = (ms) => {
              const start = Date.now();
              while (Date.now() - start < ms) {}
            };
            sleep(500);
          } else {
            throw retryUpdateError;
          }
        }
      }
      
      // Schedule retry
      setTimeout(() => sendScheduledEmail(emailId), retryDelay);
    } else {
      // Max retries reached, mark as failed (with retry for locks)
      let failedUpdateRetries = 5;
      while (failedUpdateRetries > 0) {
        try {
          stmts.updateStatus.run(
            'failed',
            null,
            new Date().toISOString(),
            error.message,
            retryCount,
            emailId
          );
          stmts.addHistory.run(emailId, 'failed', new Date().toISOString(), error.message);
          break;
        } catch (failedUpdateError) {
          const isLocked = failedUpdateError.message && (
            failedUpdateError.message.includes('locked') || 
            failedUpdateError.message.includes('SQLITE_BUSY') ||
            failedUpdateError.code === 'SQLITE_BUSY'
          );
          if (isLocked && failedUpdateRetries > 1) {
            failedUpdateRetries--;
            const sleep = (ms) => {
              const start = Date.now();
              while (Date.now() - start < ms) {}
            };
            sleep(500);
          } else {
            throw failedUpdateError;
          }
        }
      }
    }
  }
}

/**
 * Cancel a scheduled email
 */
function cancelScheduledEmail(emailId) {
  const email = stmts.getById.get(emailId);
  
  if (!email) {
    return { success: false, error: 'Scheduled email not found' };
  }
  
  if (email.status !== 'scheduled') {
    return { success: false, error: `Email status is ${email.status}, cannot cancel` };
  }
  
  // Cancel timer if exists
  const timer = activeTimers.get(emailId);
  if (timer) {
    clearTimeout(timer);
    activeTimers.delete(emailId);
  }
  
  // Update database
  stmts.cancel.run(emailId);
  stmts.addHistory.run(emailId, 'cancelled', new Date().toISOString(), null);
  
  console.log(`❌ Cancelled scheduled email: ${emailId}`);
  return { success: true, emailId };
}

/**
 * Process pending emails (polling mechanism for reliability)
 * This runs periodically to catch emails that should be sent
 * Runs independently of the main server
 */
function processPendingEmails() {
  try {
    const now = new Date().toISOString();
    const pending = stmts.getPending.all(now, 50); // Process up to 50 at a time
    
    if (pending.length === 0) {
      return; // No pending emails
    }
    
    console.log(`📬 Email scheduler: Found ${pending.length} pending emails to process`);
    
    for (const email of pending) {
      // Check if already being processed
      if (activeTimers.has(email.id)) {
        continue;
      }
      
      const scheduledTime = new Date(email.scheduled_for);
      const delayMs = scheduledTime.getTime() - Date.now();
      
      if (delayMs <= 0) {
        // Past due, send immediately
        console.log(`📧 Email scheduler: Sending past-due email ${email.id}`);
        sendScheduledEmail(email.id);
      } else if (delayMs <= 24 * 60 * 60 * 1000) { // Within 24 hours
        // Schedule for near future
        const timeoutId = setTimeout(() => {
          sendScheduledEmail(email.id);
          activeTimers.delete(email.id);
        }, delayMs);
        
        activeTimers.set(email.id, timeoutId);
        console.log(`📅 Email scheduler: Scheduled email ${email.id} for ${Math.round(delayMs / 1000)} seconds`);
      }
      // If beyond 24 hours, will be picked up in next polling cycle
    }
    
    console.log(`✅ Email scheduler: Processed ${pending.length} pending emails`);
  } catch (error) {
    console.error('❌ Email scheduler: Error processing pending emails:', error);
  }
}

/**
 * Load pending emails on startup and reschedule them
 */
function loadPendingScheduledEmails() {
  try {
    const now = new Date().toISOString();
    const pending = stmts.getPending.all(now, 1000);
    
    let loaded = 0;
    for (const email of pending) {
      const scheduledTime = new Date(email.scheduled_for);
      const delayMs = scheduledTime.getTime() - Date.now();
      
      if (delayMs <= 0) {
        // Past due, send immediately
        sendScheduledEmail(email.id);
      } else if (delayMs <= 24 * 24 * 60 * 60 * 1000) {
        // Within ~24 days, use setTimeout
        const timeoutId = setTimeout(() => {
          sendScheduledEmail(email.id);
          activeTimers.delete(email.id);
        }, delayMs);
        
        activeTimers.set(email.id, timeoutId);
        loaded++;
      }
      // Beyond 24 days will be picked up by polling
    }
    
    console.log(`📅 Loaded ${loaded} pending scheduled emails from database`);
    
    // NOTE: Polling is now handled by email-scheduler-standalone.js
    // If running standalone, polling happens there
    // If running in server, we can still enable polling here if needed
    const ENABLE_POLLING_IN_SERVER = process.env.ENABLE_EMAIL_POLLING === 'true';
    
    if (ENABLE_POLLING_IN_SERVER) {
      // Start periodic polling (every 1 minute for faster processing)
      setInterval(() => {
        processPendingEmails();
      }, 60 * 1000); // Every 1 minute
      
      console.log('✅ Email scheduler: Started polling every 1 minute (in-server mode)');
      
      // Process immediately on startup
      processPendingEmails();
      
      // Also run cleanup daily
      setInterval(() => {
        const result = stmts.cleanup.run();
        if (result.changes > 0) {
          console.log(`🧹 Cleaned up ${result.changes} old email records`);
        }
      }, 24 * 60 * 60 * 1000); // Daily
    } else {
      console.log('ℹ️ Email scheduler: Polling disabled (use email-scheduler-standalone.js for independent operation)');
    }
  } catch (error) {
    console.error('Error loading scheduled emails:', error);
  }
}

// Only load pending emails and start polling if explicitly enabled
// Otherwise, rely on email-scheduler-standalone.js for processing
if (process.env.ENABLE_EMAIL_POLLING === 'true') {
  loadPendingScheduledEmails();
} else {
  console.log('ℹ️ Email scheduler module loaded (polling disabled - use standalone script)');
}

// Export functions
module.exports = {
  scheduleEmail,
  cancelScheduledEmail,
  loadPendingScheduledEmails,
  processPendingEmails,
  db // Expose db for queries if needed
};

