const ldap = require('ldapjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Configuration
const AD_CONFIG = {
    url: 'ldaps://192.168.10.208:636',
    baseDN: 'DC=idcc,DC=local',
    domain: 'IDCC.local',
    serviceAccount: {
        username: 'pyldap@idcc.local',
        password: 'Interborough1'
    }
};

// Authorized AD Groups for Dashboard Access
// Users must be in at least ONE of these groups
const AUTHORIZED_GROUPS = [
    'PowerBI-Executive Staff',           // Executive dashboard access
    'Flatbush-SSLVPN-Users',             // VPN users (testing)
    'Flatbush_ext-SSLVPN-Users',         // Extended VPN users (testing)
    // Add more groups as needed
];

// Set to true to require group membership, false to allow all authenticated users
const REQUIRE_GROUP_MEMBERSHIP = true;

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '8h'; // Token expires after 8 hours

// Audit log directory
const AUDIT_LOG_DIR = path.join(__dirname, 'audit-logs');

// Ensure audit log directory exists
if (!fs.existsSync(AUDIT_LOG_DIR)) {
    fs.mkdirSync(AUDIT_LOG_DIR, { recursive: true });
    console.log(`[AUDIT] Created audit log directory: ${AUDIT_LOG_DIR}`);
}

// Audit log storage (in-memory for quick access, also persisted to file)
const auditLog = [];

/**
 * Write audit log to persistent file (HIPAA compliant)
 */
function writeAuditLogToFile(entry) {
    try {
        // Create daily log file (YYYY-MM-DD format)
        const date = new Date().toISOString().split('T')[0];
        const logFileName = `audit-${date}.jsonl`;
        const logFilePath = path.join(AUDIT_LOG_DIR, logFileName);
        
        // Append log entry as JSON line
        const logLine = JSON.stringify(entry) + '\n';
        fs.appendFileSync(logFilePath, logLine, 'utf8');
        
    } catch (error) {
        console.error('[AUDIT] Failed to write audit log to file:', error);
    }
}

function logAudit(event, username, success, ip, details = '') {
    const entry = {
        timestamp: new Date().toISOString(),
        event,
        username,
        success,
        ip,
        details,
        serverTime: Date.now()
    };
    
    // Add to in-memory log for quick access
    auditLog.push(entry);
    
    // Write to persistent file for HIPAA compliance
    writeAuditLogToFile(entry);
    
    // Console log for debugging
    console.log(`[AUDIT] ${event} | User: ${username} | Success: ${success} | IP: ${ip} | ${details}`);
    
    // Keep only last 1000 entries in memory (files are permanent)
    if (auditLog.length > 1000) {
        auditLog.shift();
    }
}

// Track failed login attempts (in-memory, should be database)
const failedAttempts = new Map(); // username -> { count, lockoutUntil }

function isAccountLocked(username) {
    const attempts = failedAttempts.get(username);
    if (!attempts) return false;
    
    // Check if lockout has expired
    if (attempts.lockoutUntil && new Date() > attempts.lockoutUntil) {
        failedAttempts.delete(username);
        return false;
    }
    
    return attempts.count >= 5;
}

function recordFailedAttempt(username) {
    const attempts = failedAttempts.get(username) || { count: 0, lockoutUntil: null };
    attempts.count++;
    
    // Lock account for 15 minutes after 5 failed attempts
    if (attempts.count >= 5) {
        attempts.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000);
        console.log(`[SECURITY] Account locked for 15 minutes: ${username}`);
    }
    
    failedAttempts.set(username, attempts);
}

function clearFailedAttempts(username) {
    failedAttempts.delete(username);
}

/**
 * Authenticate user against Active Directory
 */
async function authenticateUser(username, password, ipAddress) {
    console.log(`[AUTH] Authentication attempt for: ${username}`);
    
    // Check if account is locked
    if (isAccountLocked(username)) {
        logAudit('LOGIN_FAILED', username, false, ipAddress, 'Account locked due to failed attempts');
        throw new Error('ACCOUNT_LOCKED');
    }
    
    return new Promise((resolve, reject) => {
        // Create LDAP client with TLS options
        const client = ldap.createClient({
            url: AD_CONFIG.url,
            tlsOptions: {
                rejectUnauthorized: false // Set to true in production with proper certs
            }
        });

        // User's full DN for binding
        // Strip domain suffix if user already included it
        const cleanUsername = username.replace(/@.*$/, '');
        const userDN = `${cleanUsername}@${AD_CONFIG.domain}`;
        
        console.log(`[AUTH] Attempting bind for: ${userDN}`);
        
        // Try to bind with user credentials
        client.bind(userDN, password, (err) => {
            if (err) {
                console.error(`[AUTH] Bind failed for ${username}:`, err.message);
                recordFailedAttempt(username);
                logAudit('LOGIN_FAILED', username, false, ipAddress, `Invalid credentials: ${err.message}`);
                client.unbind();
                reject(new Error('INVALID_CREDENTIALS'));
                return;
            }

            console.log(`[AUTH] Bind successful for: ${username}`);
            
            // Search for user details
            const searchFilter = `(sAMAccountName=${cleanUsername})`;
            const searchOptions = {
                scope: 'sub',
                filter: searchFilter,
                attributes: ['cn', 'mail', 'displayName', 'memberOf', 'sAMAccountName']
            };

            client.search(AD_CONFIG.baseDN, searchOptions, (searchErr, searchRes) => {
                if (searchErr) {
                    console.error(`[AUTH] Search failed:`, searchErr);
                    client.unbind();
                    reject(new Error('SEARCH_FAILED'));
                    return;
                }

                const entries = [];
                
                searchRes.on('searchEntry', (entry) => {
                    entries.push(entry.pojo);
                });

                searchRes.on('error', (err) => {
                    console.error('[AUTH] Search error:', err);
                    client.unbind();
                    reject(new Error('SEARCH_ERROR'));
                });

                searchRes.on('end', () => {
                    client.unbind();
                    
                    if (entries.length === 0) {
                        logAudit('LOGIN_FAILED', username, false, ipAddress, 'User not found in directory');
                        reject(new Error('USER_NOT_FOUND'));
                        return;
                    }

                    const user = entries[0];
                    clearFailedAttempts(username);
                    
                    // Generate JWT token
                    const userGroups = user.attributes.find(a => a.type === 'memberOf')?.values || [];
                    
                    const tokenPayload = {
                        username: user.attributes.find(a => a.type === 'sAMAccountName')?.values?.[0] || username,
                        displayName: user.attributes.find(a => a.type === 'displayName')?.values?.[0] || username,
                        email: user.attributes.find(a => a.type === 'mail')?.values?.[0] || '',
                        groups: userGroups
                    };
                    
                    // Log user's groups for debugging (helps identify which group to use for authorization)
                    console.log('='.repeat(80));
                    console.log(`👤 USER GROUPS FOR: ${tokenPayload.username}`);
                    console.log('='.repeat(80));
                    if (userGroups.length > 0) {
                        userGroups.forEach((group, index) => {
                            // Extract just the CN (Common Name) for readability
                            const groupName = group.match(/CN=([^,]+)/)?.[1] || group;
                            console.log(`  ${index + 1}. ${groupName}`);
                            console.log(`     Full DN: ${group}`);
                        });
                    } else {
                        console.log('  No groups found');
                    }
                    console.log('='.repeat(80));
                    
                    // Check group membership authorization (if required)
                    if (REQUIRE_GROUP_MEMBERSHIP) {
                        const userGroupNames = userGroups.map(g => {
                            const match = g.match(/CN=([^,]+)/);
                            return match ? match[1] : '';
                        });
                        
                        const isAuthorized = AUTHORIZED_GROUPS.some(authGroup => 
                            userGroupNames.includes(authGroup)
                        );
                        
                        if (!isAuthorized) {
                            console.log('🚫 AUTHORIZATION DENIED - User not in authorized group');
                            console.log('   User groups:', userGroupNames.join(', '));
                            console.log('   Required: One of', AUTHORIZED_GROUPS.join(', '));
                            logAudit('AUTHORIZATION_DENIED', username, false, ipAddress, 
                                `Not in authorized group. User groups: ${userGroupNames.join(', ')}`);
                            reject(new Error('NOT_AUTHORIZED'));
                            return;
                        }
                        
                        console.log('✅ AUTHORIZATION GRANTED - User is in authorized group');
                    }

                    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
                    
                    logAudit('LOGIN_SUCCESS', username, true, ipAddress, `User authenticated and authorized successfully`);
                    
                    resolve({
                        token,
                        user: tokenPayload
                    });
                });
            });
        });

        // Handle client errors
        client.on('error', (err) => {
            console.error('[AUTH] LDAP client error:', err);
            recordFailedAttempt(username);
            logAudit('LOGIN_FAILED', username, false, ipAddress, `LDAP error: ${err.message}`);
            reject(new Error('LDAP_ERROR'));
        });
    });
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return { valid: true, user: decoded };
    } catch (err) {
        return { valid: false, error: err.message };
    }
}

/**
 * Middleware to protect routes
 */
function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logAudit('UNAUTHORIZED_ACCESS', 'anonymous', false, req.ip, `Missing token: ${req.path}`);
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    const verification = verifyToken(token);
    
    if (!verification.valid) {
        logAudit('UNAUTHORIZED_ACCESS', 'anonymous', false, req.ip, `Invalid token: ${req.path}`);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    req.user = verification.user;
    next();
}

/**
 * Get audit log (for admin review)
 * Returns recent in-memory logs or can read from persistent files
 */
function getAuditLog(limit = 100, date = null) {
    if (date) {
        // Read from specific date's log file
        try {
            const logFileName = `audit-${date}.jsonl`;
            const logFilePath = path.join(AUDIT_LOG_DIR, logFileName);
            
            if (!fs.existsSync(logFilePath)) {
                return [];
            }
            
            const fileContent = fs.readFileSync(logFilePath, 'utf8');
            const lines = fileContent.trim().split('\n').filter(line => line);
            const logs = lines.map(line => JSON.parse(line));
            
            return logs.slice(-limit).reverse();
        } catch (error) {
            console.error('[AUDIT] Failed to read audit log file:', error);
            return [];
        }
    }
    
    // Return recent in-memory logs
    return auditLog.slice(-limit).reverse();
}

/**
 * Get audit log summary statistics
 */
function getAuditLogStats(days = 30) {
    const stats = {
        totalLogins: 0,
        successfulLogins: 0,
        failedLogins: 0,
        uniqueUsers: new Set(),
        lockedAccounts: 0,
        byDate: {}
    };
    
    try {
        const files = fs.readdirSync(AUDIT_LOG_DIR);
        const logFiles = files.filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'));
        
        // Read recent log files
        logFiles.slice(-days).forEach(file => {
            const filePath = path.join(AUDIT_LOG_DIR, file);
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.trim().split('\n').filter(line => line);
            
            lines.forEach(line => {
                const entry = JSON.parse(line);
                const date = entry.timestamp.split('T')[0];
                
                if (!stats.byDate[date]) {
                    stats.byDate[date] = { total: 0, success: 0, failed: 0 };
                }
                
                if (entry.event === 'LOGIN_SUCCESS' || entry.event === 'LOGIN_FAILED') {
                    stats.totalLogins++;
                    stats.byDate[date].total++;
                    
                    if (entry.success) {
                        stats.successfulLogins++;
                        stats.byDate[date].success++;
                        stats.uniqueUsers.add(entry.username);
                    } else {
                        stats.failedLogins++;
                        stats.byDate[date].failed++;
                    }
                }
                
                if (entry.details && entry.details.includes('locked')) {
                    stats.lockedAccounts++;
                }
            });
        });
        
        stats.uniqueUsers = stats.uniqueUsers.size;
    } catch (error) {
        console.error('[AUDIT] Failed to generate stats:', error);
    }
    
    return stats;
}

module.exports = {
    authenticateUser,
    verifyToken,
    requireAuth,
    logAudit,
    getAuditLog,
    getAuditLogStats,
    JWT_SECRET
};

