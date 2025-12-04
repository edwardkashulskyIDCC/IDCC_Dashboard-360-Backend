const fs = require('fs');
const path = require('path');
const { sendEmailRawSMTP } = require('./email-service');

// Directory to store scheduled emails
const SCHEDULED_EMAILS_DIR = path.join(__dirname, 'scheduled-emails');
if (!fs.existsSync(SCHEDULED_EMAILS_DIR)) {
  fs.mkdirSync(SCHEDULED_EMAILS_DIR, { recursive: true });
}

// In-memory map of scheduled emails (for active monitoring)
const scheduledEmails = new Map();

/**
 * Schedule an email to be sent at a future date/time
 * @param {Object} emailData - Email details
 * @param {Date} sendDate - When to send the email
 * @returns {Promise<Object>} Scheduled email info
 */
function scheduleEmail(emailData, sendDate) {
  const now = new Date();
  const scheduleTime = new Date(sendDate);
  
  if (scheduleTime <= now) {
    throw new Error('Send date must be in the future');
  }
  
  // Generate unique ID for this scheduled email
  const emailId = `scheduled-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const delayMs = scheduleTime.getTime() - now.getTime();
  
  // Store email data
  const scheduledEmail = {
    id: emailId,
    emailData: emailData,
    scheduledFor: scheduleTime.toISOString(),
    createdAt: now.toISOString(),
    status: 'scheduled'
  };
  
  // Save to file (for persistence across server restarts)
  const filePath = path.join(SCHEDULED_EMAILS_DIR, `${emailId}.json`);
  fs.writeFileSync(filePath, JSON.stringify(scheduledEmail, null, 2));
  
  // Schedule the email
  const timeoutId = setTimeout(async () => {
    try {
      console.log(`📧 Sending scheduled email: ${emailId}`);
      await sendEmailRawSMTP(emailData);
      
      // Mark as sent
      scheduledEmail.status = 'sent';
      scheduledEmail.sentAt = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(scheduledEmail, null, 2));
      
      // Remove from active map
      scheduledEmails.delete(emailId);
      
      console.log(`✅ Scheduled email sent successfully: ${emailId}`);
    } catch (error) {
      console.error(`❌ Failed to send scheduled email ${emailId}:`, error);
      
      // Mark as failed
      scheduledEmail.status = 'failed';
      scheduledEmail.error = error.message;
      scheduledEmail.failedAt = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(scheduledEmail, null, 2));
      
      scheduledEmails.delete(emailId);
    }
  }, delayMs);
  
  // Store in memory
  scheduledEmails.set(emailId, {
    timeoutId: timeoutId,
    scheduledEmail: scheduledEmail
  });
  
  console.log(`📅 Email scheduled: ${emailId} for ${scheduleTime.toISOString()} (${Math.round(delayMs / 1000 / 60)} minutes from now)`);
  
  return {
    success: true,
    emailId: emailId,
    scheduledFor: scheduleTime.toISOString(),
    delayMinutes: Math.round(delayMs / 1000 / 60)
  };
}

/**
 * Cancel a scheduled email
 */
function cancelScheduledEmail(emailId) {
  const scheduled = scheduledEmails.get(emailId);
  if (scheduled) {
    clearTimeout(scheduled.timeoutId);
    scheduledEmails.delete(emailId);
    
    // Update file
    const filePath = path.join(SCHEDULED_EMAILS_DIR, `${emailId}.json`);
    if (fs.existsSync(filePath)) {
      const emailData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      emailData.status = 'cancelled';
      emailData.cancelledAt = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(emailData, null, 2));
    }
    
    console.log(`❌ Cancelled scheduled email: ${emailId}`);
    return { success: true, emailId };
  }
  
  return { success: false, error: 'Scheduled email not found' };
}

/**
 * Load scheduled emails from disk (on server restart)
 * Reschedules emails that haven't been sent yet
 */
function loadPendingScheduledEmails() {
  try {
    const files = fs.readdirSync(SCHEDULED_EMAILS_DIR);
    let loaded = 0;
    
    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(SCHEDULED_EMAILS_DIR, file);
          const emailData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          
          // Only reschedule if status is 'scheduled' and time hasn't passed
          if (emailData.status === 'scheduled') {
            const scheduledTime = new Date(emailData.scheduledFor);
            const now = new Date();
            
            if (scheduledTime > now) {
              // Reschedule it
              const delayMs = scheduledTime.getTime() - now.getTime();
              const timeoutId = setTimeout(async () => {
                try {
                  console.log(`📧 Sending scheduled email: ${emailData.id}`);
                  await sendEmailRawSMTP(emailData.emailData);
                  
                  emailData.status = 'sent';
                  emailData.sentAt = new Date().toISOString();
                  fs.writeFileSync(filePath, JSON.stringify(emailData, null, 2));
                  
                  scheduledEmails.delete(emailData.id);
                  console.log(`✅ Scheduled email sent: ${emailData.id}`);
                } catch (error) {
                  console.error(`❌ Failed to send scheduled email ${emailData.id}:`, error);
                  emailData.status = 'failed';
                  emailData.error = error.message;
                  emailData.failedAt = new Date().toISOString();
                  fs.writeFileSync(filePath, JSON.stringify(emailData, null, 2));
                  scheduledEmails.delete(emailData.id);
                }
              }, delayMs);
              
              scheduledEmails.set(emailData.id, {
                timeoutId: timeoutId,
                scheduledEmail: emailData
              });
              
              loaded++;
            } else {
              // Past due - mark as expired
              emailData.status = 'expired';
              emailData.expiredAt = new Date().toISOString();
              fs.writeFileSync(filePath, JSON.stringify(emailData, null, 2));
            }
          }
        } catch (error) {
          console.error(`Error loading scheduled email ${file}:`, error);
        }
      }
    }
    
    console.log(`📅 Loaded ${loaded} pending scheduled emails`);
  } catch (error) {
    console.error('Error loading scheduled emails:', error);
  }
}

// Load pending emails on module load
loadPendingScheduledEmails();

module.exports = {
  scheduleEmail,
  cancelScheduledEmail,
  loadPendingScheduledEmails
};

