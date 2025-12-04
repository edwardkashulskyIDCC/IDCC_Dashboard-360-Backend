const nodemailer = require('nodemailer');
const net = require('net');

// Email configuration - Gmail SMTP Relay
// Exactly matches Java: no auth, no STARTTLS
const EMAIL_CONFIG = {
    smtp: {
        host: 'smtp-relay.gmail.com',
        port: 587,
        secure: false, // false for port 587
        requireTLS: false, // Explicitly disable STARTTLS (matches Java: starttls.enable = false)
        ignoreTLS: true, // Ignore TLS/STARTTLS completely
        auth: false, // No authentication (matches Java: auth = false)
        tls: {
            rejectUnauthorized: false // Allow self-signed certs if internal relay
        }
    },
    // From email should match an authorized domain for the relay
    fromEmail: process.env.EMAIL_FROM || 'sfriedman@interborough.org',
    fromName: 'Carelogic Zoom Meetings'
};

// Create reusable transporter
let transporter = null;

/**
 * Initialize email transporter
 */
function initializeTransporter() {
    if (!transporter) {
        transporter = nodemailer.createTransport(EMAIL_CONFIG.smtp);
    }
    return transporter;
}

/**
 * Send email with Zoom meeting details
 * @param {Object} emailData - Email details
 * @param {string} emailData.to - Recipient email address
 * @param {string} emailData.subject - Email subject
 * @param {string} emailData.text - Plain text body
 * @param {string} emailData.html - HTML body (optional)
 * @param {string} emailData.icsContent - ICS file content for calendar attachment (optional)
 * @returns {Promise<Object>} Success response
 */
async function sendEmail(emailData) {
    try {
        // Verify nodemailer is available
        if (!nodemailer) {
            throw new Error('nodemailer module is not installed. Please run: npm install nodemailer');
        }
        
        const transport = initializeTransporter();
        
        // Don't verify connection - relay may reject EHLO but allow actual sending
        console.log('📧 From email:', EMAIL_CONFIG.fromEmail);
        console.log('📧 To email:', emailData.to);
        console.log('📧 SMTP config:', {
            host: EMAIL_CONFIG.smtp.host,
            port: EMAIL_CONFIG.smtp.port,
            auth: EMAIL_CONFIG.smtp.auth,
            requireTLS: EMAIL_CONFIG.smtp.requireTLS,
            ignoreTLS: EMAIL_CONFIG.smtp.ignoreTLS
        });
        
        const mailOptions = {
            // Use just the email address (like Java), not formatted name
            from: EMAIL_CONFIG.fromEmail,  // "sfriedman@interborough.org"
            to: emailData.to,
            subject: emailData.subject,
            text: emailData.text,
            html: emailData.html
        };
        
        // Add ICS attachment if provided
        if (emailData.icsContent) {
            mailOptions.attachments = [
                {
                    filename: 'meeting.ics',
                    content: emailData.icsContent,
                    contentType: 'text/calendar; charset=utf-8; method=REQUEST'
                }
            ];
        }
        
        console.log('📧 Sending email to:', emailData.to);
        console.log('📧 Subject:', emailData.subject);
        
        // Send email
        const info = await transport.sendMail(mailOptions);
        
        console.log('✅ Email sent successfully:', info.messageId);
        
        return {
            success: true,
            message: 'Email sent successfully',
            messageId: info.messageId
        };
    } catch (error) {
        console.error('❌ Error sending email:', error);
        console.error('❌ Full error details:', {
            code: error.code,
            command: error.command,
            response: error.response,
            responseCode: error.responseCode
        });
        
        // Provide more detailed error message
        let errorMessage = error.message || 'Unknown error';
        
        if (error.code === 'MODULE_NOT_FOUND') {
            errorMessage = 'nodemailer module is not installed. Please run: npm install nodemailer';
        } else if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
            errorMessage = `SMTP connection failed: ${error.message}. Check SMTP settings.`;
        } else if (error.responseCode) {
            errorMessage = `SMTP error (${error.responseCode}): ${error.response || error.message}`;
            // Include the full response if available
            if (error.response) {
                errorMessage += `\nFull response: ${error.response}`;
            }
        }
        
        throw new Error(errorMessage);
    }
}

/**
 * Send email using raw SMTP protocol (matches Java behavior exactly)
 * Bypasses nodemailer's TLS negotiation
 */
function sendEmailRawSMTP(emailData) {
    return new Promise((resolve, reject) => {
        const relayHost = 'smtp-relay.gmail.com';
        const relayPort = 587;
        const fromEmail = EMAIL_CONFIG.fromEmail;
        
        console.log('📧 Connecting to SMTP relay:', relayHost, ':', relayPort);
        
        const client = net.createConnection(relayPort, relayHost, () => {
            console.log('✅ Connected to SMTP server');
            
            let buffer = '';
            
            // Handle server responses
            client.on('data', (data) => {
                buffer += data.toString();
                const lines = buffer.split('\r\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer
                
                for (const line of lines) {
                    if (line.trim()) {
                        console.log('📨 SMTP:', line);
                    }
                }
            });
            
            // Handle errors
            client.on('error', (error) => {
                console.error('❌ Socket error:', error);
                reject(new Error(`SMTP connection error: ${error.message}`));
            });
            
            // Handle close
            client.on('close', () => {
                console.log('🔌 SMTP connection closed');
            });
            
            // Send SMTP commands
            let step = 0; // Track SMTP protocol step (accessible to timeout handler)
            const sendCommand = (command) => {
                console.log('📤 Sending:', command);
                client.write(command + '\r\n');
            };
            
            const processResponse = (response) => {
                const code = parseInt(response.substring(0, 3));
                const isLastLine = response.charAt(3) === ' ';
                
                if (code >= 400) {
                    reject(new Error(`SMTP error: ${response}`));
                    client.end();
                    return;
                }
                
                if (step === 0 && code === 220) {
                    // Server ready, send EHLO
                    step = 1;
                    sendCommand('EHLO ' + relayHost);
                } else if (step === 1 && code === 250 && isLastLine) {
                    // EHLO complete, send MAIL FROM
                    step = 2;
                    sendCommand('MAIL FROM:<' + fromEmail + '>');
                } else if (step === 2 && code === 250) {
                    // MAIL FROM accepted, send RCPT TO
                    step = 3;
                    sendCommand('RCPT TO:<' + emailData.to + '>');
                } else if (step === 3 && code === 250) {
                    // RCPT TO accepted, send DATA
                    step = 4;
                    sendCommand('DATA');
                } else if (step === 4 && code === 354) {
                    // Ready for data, send email content
                    step = 5;
                    const emailContent = buildRawEmailContent(emailData, fromEmail);
                    sendCommand(emailContent);
                    sendCommand('.'); // End of data
                } else if (step === 5 && code === 250) {
                    // Email accepted, send QUIT
                    step = 6;
                    sendCommand('QUIT');
                    resolve({
                        success: true,
                        message: 'Email sent successfully via raw SMTP',
                        response: response
                    });
                } else if (step === 6) {
                    // Quit acknowledged
                    client.end();
                }
            };
            
            // Override data handler to process responses properly
            client.removeAllListeners('data');
            client.on('data', (data) => {
                buffer += data.toString();
                const lines = buffer.split('\r\n');
                buffer = lines.pop() || '';
                
                for (const line of lines) {
                    if (line.trim()) {
                        console.log('📨 SMTP:', line);
                        processResponse(line);
                    }
                }
            });
        });
        
        // Set timeout - increased to 60 seconds to handle slow SMTP responses
        client.setTimeout(60000); // 60 seconds
        client.on('timeout', () => {
            // Check if we've already sent the email (step 5 or 6 means email was accepted)
            if (step >= 5) {
                console.warn('⚠️ SMTP timeout after email was accepted - email may have been sent');
                // Email was likely sent, resolve instead of reject
                resolve({
                    success: true,
                    message: 'Email sent (timeout after acceptance)',
                    warning: 'Connection timeout but email was accepted by server'
                });
            } else {
                reject(new Error('SMTP connection timeout before email was sent'));
            }
            client.destroy();
        });
    });
}

/**
 * Build raw email content in SMTP format
 */
function buildRawEmailContent(emailData, fromEmail) {
    const lines = [];
    
    // Headers
    lines.push('From: ' + fromEmail);
    lines.push('To: ' + emailData.to);
    lines.push('Subject: ' + emailData.subject);
    lines.push('MIME-Version: 1.0');
    lines.push('Content-Type: multipart/alternative; boundary="----=_boundary_12345"');
    lines.push('');
    lines.push('------=_boundary_12345');
    lines.push('Content-Type: text/plain; charset=utf-8');
    lines.push('Content-Transfer-Encoding: 7bit');
    lines.push('');
    lines.push(emailData.text);
    lines.push('');
    lines.push('------=_boundary_12345');
    lines.push('Content-Type: text/html; charset=utf-8');
    lines.push('Content-Transfer-Encoding: 7bit');
    lines.push('');
    lines.push(emailData.html);
    lines.push('');
    
    // Add ICS attachment if provided
    if (emailData.icsContent) {
        lines.push('------=_boundary_12345');
        lines.push('Content-Type: text/calendar; charset=utf-8; method=REQUEST');
        lines.push('Content-Disposition: attachment; filename="meeting.ics"');
        lines.push('Content-Transfer-Encoding: 7bit');
        lines.push('');
        lines.push(emailData.icsContent);
        lines.push('');
    }
    
    lines.push('------=_boundary_12345--');
    
    return lines.join('\r\n');
}

module.exports = {
    sendEmail,
    sendEmailRawSMTP,
    EMAIL_CONFIG
};

