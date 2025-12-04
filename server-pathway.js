const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const crypto = require('crypto');
const snowflake = require('snowflake-sdk');
const sql = require('mssql');
const { authenticateUser, verifyToken, requireAuth, logAudit, getAuditLog, getAuditLogStats } = require('./auth-service');
const { scheduleEmail } = require('./email-scheduler-db');

// Set up file logging (truncate on each start)
const logFile = 'server-debug.log';
const logStream = fs.createWriteStream(logFile, { flags: 'w' });

// Override console.log to write to both console and file
const originalConsoleLog = console.log;
console.log = function(...args) {
    const timestamp = new Date().toISOString();
    // Convert args to strings, handling objects properly
    const messageParts = args.map(arg => {
        if (typeof arg === 'object' && arg !== null) {
            try {
                return JSON.stringify(arg);
            } catch (e) {
                return String(arg);
            }
        }
        return String(arg);
    });
    const message = `[${timestamp}] ${messageParts.join(' ')}\n`;
    logStream.write(message);
    originalConsoleLog.apply(console, args);
};

// Override console.error to write to both console and file
const originalConsoleError = console.error;
console.error = function(...args) {
    const timestamp = new Date().toISOString();
    const message = `[${timestamp}] ERROR: ${args.join(' ')}\n`;
    logStream.write(message);
    originalConsoleError.apply(console, args);
};

const app = express();
app.use(cors());
app.use(express.json()); // Parse JSON bodies

// ========================================
// CONSTANTS & CONFIGURATION
// ========================================

// Standard location lists used across multiple endpoints
const STANDARD_LOCATIONS = ["Flatbush", "Crown Heights", "Williamsburg", "Canarsie", "Coney Island", "Home Based", "Schools", "Iop", "ACT"];
const STANDARD_LOCATIONS_WITH_EMPTY = ["", ...STANDARD_LOCATIONS];
const LOCATIONS_WITH_LSA = ["", "Flatbush", "Crown Heights", "Williamsburg", "Canarsie", "Coney Island", "Home Based", "Schools", "LSA Midwood", "LSA Coney", "LSA Crown Heights", "LSA Williamsburg", "LSA Community"];
const ORGANIZATION_LOCATIONS = ["Flatbush", "Crown Heights", "Williamsburg", "Canarsie", "Coney Island", "Home Based", "ACT"];

// ========================================
// HELPER FUNCTIONS
// ========================================

/**
 * Middleware to check if Snowflake connection is ready
 * Returns 503 if not ready, otherwise continues to next middleware
 */
function requireSnowflakeReady(req, res, next) {
    if (!snowflakeReady) {
        console.error(' Snowflake connection not ready');
        return res.status(503).json({ 
            error: 'Database connection not ready. Please try again in a moment.' 
        });
    }
    next();
}

/**
 * Execute a Snowflake query with standardized error handling
 * @param {string} sqlText - SQL query to execute
 * @param {Object} options - Options object
 * @param {Function} options.onSuccess - Callback for successful query (rows, res)
 * @param {Function} options.onError - Optional custom error handler (err, res)
 * @param {Object} res - Express response object
 * @param {string} errorMessage - Error message to return on failure
 */
function executeSnowflakeQuery(sqlText, { onSuccess, onError }, res, errorMessage = 'Failed to execute query') {
    connection.execute({
        sqlText: sqlText,
        complete: function(err, stmt, rows) {
            if (err) {
                console.error(` Query error:`, err);
                if (onError) {
                    return onError(err, res);
                }
                return res.status(500).json({ 
                    error: errorMessage,
                    details: err.message 
                });
            }
            
            console.log(`Query returned ${rows ? rows.length : 0} rows`);
            onSuccess(rows || [], res);
        }
    });
}

/**
 * Standard error response helpers
 */
const errorResponses = {
    snowflakeNotReady: (res) => res.status(503).json({ 
        error: 'Database connection not ready. Please try again in a moment.' 
    }),
    serverError: (res, message = 'Internal server error', details = null) => {
        const response = { error: message };
        if (details) response.details = details;
        return res.status(500).json(response);
    },
    badRequest: (res, message = 'Bad request') => res.status(400).json({ error: message }),
    notFound: (res, message = 'Not found') => res.status(404).json({ error: message })
};

// ========================================
// AUTHENTICATION ENDPOINTS
// ========================================

// Login endpoint - No auth required
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    
    if (!username || !password) {
        logAudit('LOGIN_FAILED', username || 'unknown', false, ipAddress, 'Missing credentials');
        return errorResponses.badRequest(res, 'Username and password required');
    }
    
    try {
        const result = await authenticateUser(username, password, ipAddress);
        res.json(result);
    } catch (err) {
        const errorMap = {
            'ACCOUNT_LOCKED': 'Account temporarily locked due to failed login attempts. Try again in 15 minutes.',
            'INVALID_CREDENTIALS': 'Invalid username or password',
            'USER_NOT_FOUND': 'User not found',
            'NOT_AUTHORIZED': 'Access denied. You are not authorized to use this dashboard. Please contact IT if you need access.',
            'LDAP_ERROR': 'Authentication service unavailable. Please try again later.',
            'SEARCH_FAILED': 'Unable to retrieve user information',
            'SEARCH_ERROR': 'Directory search error'
        };
        
        const message = errorMap[err.message] || 'Authentication failed';
        res.status(401).json({ error: message });
    }
});

// Verify token endpoint - No auth required (it's verifying itself)
app.post('/api/auth/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return errorResponses.badRequest(res, 'Token required');
    }
    
    const verification = verifyToken(token);
    
    if (verification.valid) {
        res.json({ valid: true, user: verification.user });
    } else {
        res.status(401).json({ valid: false, error: verification.error });
    }
});

// Logout endpoint - Logs the event (client will discard token)
app.post('/api/auth/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const verification = verifyToken(token);
        if (verification.valid) {
            logAudit('LOGOUT', verification.user.username, true, req.ip, 'User logged out');
        }
    }
    res.json({ success: true });
});

// Get audit log - Protected endpoint for admins
app.get('/api/auth/audit-log', requireAuth, (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const date = req.query.date || null; // Optional: YYYY-MM-DD format
    
    logAudit('AUDIT_LOG_ACCESS', req.user.username, true, req.ip, `Viewing audit log (${limit} entries, date: ${date || 'recent'})`);
    
    const logs = getAuditLog(limit, date);
    res.json({ 
        logs, 
        count: logs.length,
        date: date || 'recent',
        message: date ? `Logs from ${date}` : 'Recent logs from memory'
    });
});

// Get audit log statistics - Protected endpoint for admins
app.get('/api/auth/audit-stats', requireAuth, (req, res) => {
    const days = parseInt(req.query.days) || 30;
    logAudit('AUDIT_STATS_ACCESS', req.user.username, true, req.ip, `Viewing audit stats (${days} days)`);
    
    const stats = getAuditLogStats(days);
    res.json({ 
        stats,
        period: `Last ${days} days`,
        generated: new Date().toISOString()
    });
});

// ========================================
// VIEWED CLIENTS TRACKING
// ========================================

// Create viewed-clients directory if it doesn't exist
const VIEWED_CLIENTS_DIR = path.join(__dirname, 'viewed-clients');
if (!fs.existsSync(VIEWED_CLIENTS_DIR)) {
    fs.mkdirSync(VIEWED_CLIENTS_DIR, { recursive: true });
    console.log(' Created viewed-clients directory');
}

// Helper: Write viewed client event to file (JSONL format)
function logViewedClient(username, clientId, page, ip) {
    try {
        const timestamp = new Date().toISOString();
        const date = timestamp.split('T')[0]; // YYYY-MM-DD
        const fileName = `viewed-${date}.jsonl`;
        const filePath = path.join(VIEWED_CLIENTS_DIR, fileName);
        
        const entry = {
            timestamp,
            username,
            clientId: String(clientId),
            page,
            ip
        };
        
        fs.appendFileSync(filePath, JSON.stringify(entry) + '\n', 'utf8');
    } catch (err) {
        console.error('Failed to log viewed client:', err);
    }
}

// Helper: Get viewed clients for a user (last N days) with timestamps
function getViewedClients(username, days = 7) {
    const viewedClientsMap = new Map(); // clientId -> { timestamp, page, action }
    const now = new Date();
    
    try {
        // Read files from last N days (oldest to newest)
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            const fileName = `viewed-${dateStr}.jsonl`;
            const filePath = path.join(VIEWED_CLIENTS_DIR, fileName);
            
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                const lines = content.trim().split('\n').filter(line => line);
                
                lines.forEach(line => {
                    try {
                        const entry = JSON.parse(line);
                        if (entry.username === username) {
                            const existing = viewedClientsMap.get(entry.clientId);
                            
                            // Process entries chronologically - most recent action wins
                            if (!existing || new Date(entry.timestamp) > new Date(existing.timestamp)) {
                                if (entry.action === 'CLEARED') {
                                    // If cleared, remove from map
                                    viewedClientsMap.delete(entry.clientId);
                                } else {
                                    // Normal view - add/update
                                    viewedClientsMap.set(entry.clientId, {
                                        timestamp: entry.timestamp,
                                        page: entry.page || 'unknown'
                                    });
                                }
                            }
                        }
                    } catch (e) {
                        // Skip invalid JSON lines
                    }
                });
            }
        }
    } catch (err) {
        console.error('Failed to read viewed clients:', err);
    }
    
    // Convert Map to object for JSON response
    const result = {};
    viewedClientsMap.forEach((value, clientId) => {
        result[clientId] = value;
    });
    
    return result;
}

// Mark client as viewed - Protected endpoint
app.post('/api/mark-client-viewed', requireAuth, (req, res) => {
    const { clientId, page } = req.body;
    const username = req.user.username;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!clientId || !page) {
        return res.status(400).json({ error: 'clientId and page are required' });
    }
    
    logViewedClient(username, clientId, page, ip);
    res.json({ success: true, clientId, page });
});

// Get viewed clients for current user - Protected endpoint
app.get('/api/viewed-clients', requireAuth, (req, res) => {
    const username = req.user.username;
    const days = parseInt(req.query.days) || 7;
    
    const viewedClients = getViewedClients(username, days);
    res.json({ 
        viewedClients, // Object: { clientId: { timestamp, page } }
        count: Object.keys(viewedClients).length,
        days,
        username
    });
});

// Clear viewed status for a client - Protected endpoint
app.delete('/api/mark-client-viewed/:clientId', requireAuth, (req, res) => {
    const { clientId } = req.params;
    const username = req.user.username;
    
    if (!clientId) {
        return errorResponses.badRequest(res, 'clientId is required');
    }
    
    // Note: We're not actually deleting from files (append-only logs for audit)
    // Instead, we'll log a "CLEARED" event that the frontend will respect
    const timestamp = new Date().toISOString();
    const date = timestamp.split('T')[0];
    const fileName = `viewed-${date}.jsonl`;
    const filePath = path.join(VIEWED_CLIENTS_DIR, fileName);
    
    const entry = {
        timestamp,
        username,
        clientId: String(clientId),
        action: 'CLEARED',
        ip: req.ip || req.connection.remoteAddress
    };
    
    try {
        fs.appendFileSync(filePath, JSON.stringify(entry) + '\n', 'utf8');
        res.json({ success: true, clientId, action: 'cleared' });
    } catch (err) {
        console.error('Failed to clear viewed client:', err);
        errorResponses.serverError(res, 'Failed to clear viewed status');
    }
});

// ========================================
// GOOGLE CALENDAR API ENDPOINTS
// ========================================

// REMOVED: Google Calendar endpoints - no longer needed

// REMOVED: All Zoom and Google Calendar endpoints - no longer needed

// Historical Data Endpoint - Protected
app.get('/api/historical-data', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log('Fetching historical data...');
    const { startDate, endDate } = req.query;
    
    console.log('Date range:', { startDate, endDate });
    
    if (!startDate || !endDate) {
        console.error(' Missing date parameters');
        return errorResponses.badRequest(res, 'startDate and endDate are required');
    }
    
    const historicalQuery = `
        WITH daily_appointments AS (
            SELECT 
                TO_DATE(mv_sa.actual_begin_datetime) AS scheduled_date,
                mv_sa.actual_begin_datetime AS scheduled_datetime,
                mv_sa.client_id,
                mv_sa.staff_id,
                mv_sa.activity_log_id
            FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
            WHERE TO_DATE(mv_sa.actual_begin_datetime) >= '${startDate}'
              AND TO_DATE(mv_sa.actual_begin_datetime) <= '${endDate}'
        ),
        daily_with_actuals AS (
            SELECT DISTINCT
                da.scheduled_date,
                da.client_id,
                da.staff_id,
                da.activity_log_id,
                al.organization_id,
                -- Convert statuses to match weekly-risk-analysis logic
                CASE 
                    WHEN ad.status = 'Kept' THEN 'Kept'
                    WHEN ad.status IN ('DNS', 'CBC', 'CBT') THEN 'Missed'
                    ELSE 'Scheduled' 
                END AS appointment_status
            FROM daily_appointments da
            JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = da.activity_log_id
            JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = da.client_id
            JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = da.staff_id
            JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
            LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
              ON ad.activity_log_id = da.activity_log_id
             AND TO_DATE(ad.actual_begin_datetime) = da.scheduled_date
            LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
            WHERE UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
        )
        SELECT 
            scheduled_date AS date,
            COUNT(*) AS total_appointments,
            SUM(CASE WHEN appointment_status = 'Kept' THEN 1 ELSE 0 END) AS kept,
            SUM(CASE WHEN appointment_status = 'Missed' THEN 1 ELSE 0 END) AS missed,
            ROUND(
                SUM(CASE WHEN appointment_status = 'Kept' THEN 1 ELSE 0 END)::FLOAT / 
                NULLIF(COUNT(*), 0) * 100, 1
            ) AS attendance,
            COUNT(DISTINCT organization_id) AS locations,
            COUNT(DISTINCT staff_id) AS staff
        FROM daily_with_actuals
        WHERE appointment_status != 'Error'
        GROUP BY scheduled_date
        ORDER BY scheduled_date ASC;
    `;
    
    console.log('Executing historical query...');
    executeSnowflakeQuery(historicalQuery, {
        onSuccess: (rows, res) => {
            console.log(` Query returned ${rows.length} rows`);
            
            // Convert to camelCase for frontend
            const formattedRows = (rows || []).map(row => {
                let dateStr = row.DATE;
                if (row.DATE instanceof Date) {
                    const d = row.DATE;
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    dateStr = `${year}-${month}-${day}`;
                }
                return {
                    date: dateStr,
                    totalAppointments: row.TOTAL_APPOINTMENTS || 0,
                    kept: row.KEPT || 0,
                    missed: row.MISSED || 0,
                    attendance: row.ATTENDANCE || 0,
                    locations: row.LOCATIONS || 0,
                    staff: row.STAFF || 0
                };
            });
            
            // Log sample for debugging
            console.log(` Returning ${formattedRows.length} days of historical data`);
            const oct21Data = formattedRows.find(r => r.date === '2025-10-21');
            if (oct21Data) {
                console.log('HISTORICAL ENDPOINT - Oct 21 data:', oct21Data);
            }
            
            // Check for duplicate activity_log_ids - use proper date comparison
            if (rows.length > 0) {
                console.log('HISTORICAL - Sample DATE value:', rows[0].DATE, 'Type:', typeof rows[0].DATE);
                const oct21Rows = rows.filter(r => {
                    if (r.DATE instanceof Date) {
                        const d = r.DATE;
                        const year = d.getFullYear();
                        const month = String(d.getMonth() + 1).padStart(2, '0');
                        const day = String(d.getDate()).padStart(2, '0');
                        const dateStr = `${year}-${month}-${day}`;
                        return dateStr === '2025-10-21';
                    }
                    return String(r.DATE) === '2025-10-21' || String(r.DATE).startsWith('2025-10-21');
                });
                console.log(`HISTORICAL - Raw rows for Oct 21: ${oct21Rows.length}`);
            }
            
            res.json(formattedRows);
        }
    }, res, 'Failed to fetch historical data');
});

// Test endpoint first - moved to the very beginning
// REMOVED: Test endpoints - not used in production
// app.get('/api/test', ...)
// app.get('/api/test-db', ...)

// Read private key PEM string
const privateKeyPem = fs.readFileSync('./rsa_key_idcc.p8', 'utf8');

const connection = snowflake.createConnection({
    account: 'tua59128.us-east-1',
    username: 'CAP_IDCC_1000_KP',
    privateKey: privateKeyPem, // Pass PEM string directly
    database: 'CARELOGIC_PROD',
    warehouse: 'CARELOGIC_CONNECTOR_NYIBDCC_WH',
    schema: 'SECURE',
    authenticator: 'SNOWFLAKE_JWT'
});

// Helper to convert UTC datetime to EST with AM/PM
// ...existing code...

// Helper to convert UTC datetime to EST with AM/PM (MM/DD/YYYY hh:mm AM/PM)
function toESTString(input) {
    if (!input) return '';
    let date;
    if (typeof input === 'string') {
        date = new Date(input.replace(' ', 'T'));
    } else if (input instanceof Date) {
        date = input;
    } else {
        return '';
    }
    // Add 4 hours
    date = new Date(date.getTime() + (4 * 60 * 60 * 1000));
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    let hour = date.getHours();
    const minute = String(date.getMinutes()).padStart(2, '0');
    const ampm = hour >= 12 ? 'PM' : 'AM';
    hour = hour % 12;
    if (hour === 0) hour = 12;
    return `${month}/${day}/${year} ${hour}:${minute} ${ampm}`;
}

// ...existing code...

// Resilient Snowflake connector with retry (do not exit server)
let snowflakeReady = false;
function connectToSnowflake(retryMs = 10000) {
    console.log(`Attempting Snowflake connection...`);
    connection.connect((err, conn) => {
        if (err) {
            console.error('Could not connect to Snowflake:', err.message);
            snowflakeReady = false;
            console.log(`Retrying Snowflake connection in ${retryMs / 1000}s...`);
            setTimeout(() => connectToSnowflake(retryMs), retryMs);
        } else {
            snowflakeReady = true;
            console.log(' Connected to Snowflake - Ready to execute queries');
            
            // Execute initial queries only AFTER connection is established
            console.log('Server starting up, executing initial queries...');
            refreshBothDatasets().catch(err => {
                console.error('Error during initial data load:', err);
            });
            
            // Notify all connected WebSocket clients that data is now available
            if (allClients.size > 0) {
                console.log(` Notifying ${allClients.size} WebSocket client(s) that Snowflake is ready`);
                allClients.forEach((clientPrefs, ws) => {
                    if (ws.readyState === WebSocket.OPEN) {
                        // Trigger query for this client's preferred view/date
                        executeQueryForDate(clientPrefs.date, clientPrefs.view);
                    }
                });
            }
        }
    });
}
connectToSnowflake();

// Lightweight health endpoint
app.get('/api/health', (req, res) => {
    res.json({ ok: true, snowflakeReady });
});

// REMOVED: /api/kept-sessions - Replaced by /api/pathway-coordinator endpoint
// This endpoint was the old implementation and is no longer used

// API endpoint to get client activity history
// Cache for client activity history (keyed by clientId)
const clientActivityHistoryCache = new Map();
const CLIENT_ACTIVITY_HISTORY_CACHE_TTL = 2 * 60 * 1000; // 2 minutes
const CLIENT_ACTIVITY_HISTORY_LIMIT = 500; // Limit to most recent 500 records

app.get('/api/client-activity-history/:clientId', requireAuth, requireSnowflakeReady, (req, res) => {
    const clientId = req.params.clientId;
    const forceRefresh = req.query.force_refresh === 'true';
    
    console.log(`Fetching activity history for client: ${clientId}`);
    
    // Check cache first
    if (!forceRefresh) {
        const cached = clientActivityHistoryCache.get(clientId);
        if (cached && (Date.now() - cached.timestamp) < CLIENT_ACTIVITY_HISTORY_CACHE_TTL) {
            console.log(`Returning cached activity history for client ${clientId}`);
            return res.json(cached.data);
        }
    }
    
    // Optimized query: Combined into single query with LEFT JOINs instead of UNION ALL
    // This is more efficient as it avoids duplicate table scans
    const activityHistoryQuery = `
        SELECT
            ad.CHANGED_DATE, 
            staff.full_name,
            a.description, 
            ad.status, 
            COALESCE(mv_Doc.first_signed, Doc.fully_signed_YN) AS signed
        FROM activity_log al 
        JOIN activity_Detail ad ON al.activity_log_id = ad.activity_log_id
        JOIN activity a ON al.activity_id = a.activity_id
        JOIN mv_Staff staff ON ad.status_by = staff.staff_id
        LEFT JOIN mv_client_document mv_Doc 
            ON mv_doc.activity_detail_id = ad.activity_Detail_id
        LEFT JOIN document Doc 
            ON doc.activity_detail_id = ad.activity_detail_id
        WHERE ad.client_id = ${clientId}
        ORDER BY ad.CHANGED_DATE DESC
        LIMIT ${CLIENT_ACTIVITY_HISTORY_LIMIT}
    `;
    
    executeSnowflakeQuery(activityHistoryQuery, {
        onSuccess: (rows, res) => {
            console.log(`Activity history query returned ${rows.length} rows for client ${clientId}`);
            
            // Cache the results
            clientActivityHistoryCache.set(clientId, {
                data: rows,
                timestamp: Date.now()
            });
            
            // Clean up old cache entries (older than 10 minutes)
            const now = Date.now();
            for (const [key, value] of clientActivityHistoryCache.entries()) {
                if (now - value.timestamp > 10 * 60 * 1000) {
                    clientActivityHistoryCache.delete(key);
                }
            }
            
            if (rows.length > 0) {
                console.log('Sample activity history row:', JSON.stringify(rows[0], null, 2));
            }
            res.json(rows);
        }
    }, res, 'Failed to fetch client activity history');
});

// REMOVED: /api/attendance-prediction - Not used in frontend
/*
app.get('/api/attendance-prediction', requireAuth, (req, res) => {
    console.log('Fetching attendance predictions...');
    
    if (!snowflakeReady) {
        console.error(' Snowflake connection not ready');
        return res.status(503).json({ error: 'Database connection not ready. Please try again in a moment.' });
    }
    
    const predictionQuery = `
            WITH base_schedule AS (
                SELECT 
                    mv_sa.client_id,
                    mv_sa.staff_id,
                    mv_sa.activity_log_id,
                    mv_sa.actual_begin_datetime AS scheduled_begin_datetime
                FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
                WHERE TO_DATE(mv_sa.actual_begin_datetime) = CURRENT_DATE()
            ),
            joined AS (
                SELECT 
                    org.name AS Location,
                    staff.staff_id,
                    staff.full_name AS Staff,
                    p.person_id,
                    p.last_name,
                    p.first_name,
                    -- Prefer actual end when present, else scheduled begin
                    COALESCE(ad.actual_end_datetime, bs.scheduled_begin_datetime) AS ACTUAL_END_DATETIME,
                    -- Use actual status if present, else treat as Scheduled
                    COALESCE(ad.status, 'Scheduled') AS appointment_status,
                    ROW_NUMBER() OVER (
                        PARTITION BY p.person_id 
                        ORDER BY COALESCE(ad.actual_end_datetime, bs.scheduled_begin_datetime) ASC
                    ) AS rn
                FROM base_schedule bs
                JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = bs.client_id
                JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = bs.staff_id
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = bs.activity_log_id
                JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
                -- Bring in today's actuals for this scheduled slot if any
                LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
                  ON ad.activity_log_id = bs.activity_log_id
                 AND TO_DATE(ad.actual_begin_datetime) = CURRENT_DATE()
                -- Exclude pathway coordination
                LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
            ),
            history_90d AS (
                SELECT
                    ad.client_id AS person_id,
                    COUNT(*) AS total_90d,
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_90d,
                    SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_90d
                FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE TO_DATE(ad.CHANGED_DATE) >= DATEADD(day, -90, CURRENT_DATE())
                  AND TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
                  AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                  AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                GROUP BY ad.client_id
            ),
            history_all AS (
                SELECT
                    ad.client_id AS person_id,
                    COUNT(*) AS total_all,
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_all,
                    SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_all
                FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                  AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                GROUP BY ad.client_id
            ),
            last_status AS (
                SELECT person_id, status AS last_status
                FROM (
                    SELECT
                        ad.client_id AS person_id,
                        ad.status,
                        ROW_NUMBER() OVER (
                            PARTITION BY ad.client_id
                            ORDER BY ad.CHANGED_DATE DESC
                        ) AS rn
                    FROM CARELOGIC_PROD.SECURE.activity_detail ad
                    JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                    JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                    WHERE TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
                      AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                      AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                ) s
                WHERE rn = 1
            )
            SELECT 
                rd.person_id AS PERSON_ID,
                rd.First_name AS FIRST_NAME,
                rd.Last_name AS LAST_NAME,
                rd.staff_id AS STAFF_ID,
                rd.Staff AS STAFF_NAME,
                rd.Location AS LOCATION,
                rd.ACTUAL_END_DATETIME AS ACTUAL_BEGIN_DATETIME,
                rd.appointment_status AS CURRENT_STATUS,
                -- Effective attendance rate: use 90d if >=3 appts, else all-time
                CASE 
                    WHEN h.total_90d IS NOT NULL AND h.total_90d >= 3 THEN (h.kept_90d::FLOAT / NULLIF(h.total_90d,0))
                    ELSE (ha.kept_all::FLOAT / NULLIF(ha.total_all,0))
                END AS ATTENDANCE_RATE,
                -- Risk score: 0..100 from effective rate; fallback 50 if no data at all
                COALESCE(ROUND(
                    100 * CASE 
                        WHEN h.total_90d IS NOT NULL AND h.total_90d >= 3 THEN (h.kept_90d::FLOAT / NULLIF(h.total_90d,0))
                        ELSE (ha.kept_all::FLOAT / NULLIF(ha.total_all,0))
                    END
                ), 50) AS RISK_SCORE,
                CASE
                    WHEN ( (h.total_90d IS NULL OR h.total_90d = 0) AND (ha.total_all IS NULL OR ha.total_all = 0) ) THEN 'Unknown'
                    WHEN (
                        CASE 
                            WHEN h.total_90d IS NOT NULL AND h.total_90d >= 3 THEN (h.kept_90d::FLOAT / NULLIF(h.total_90d,0))
                            ELSE (ha.kept_all::FLOAT / NULLIF(ha.total_all,0))
                        END
                    ) < 0.5 THEN 'High'
                    WHEN (
                        CASE 
                            WHEN h.total_90d IS NOT NULL AND h.total_90d >= 3 THEN (h.kept_90d::FLOAT / NULLIF(h.total_90d,0))
                            ELSE (ha.kept_all::FLOAT / NULLIF(ha.total_all,0))
                        END
                    ) < 0.8 THEN 'Medium'
                    ELSE 'Low'
                END AS RISK_LEVEL,
                -- Expose components for UI explanation
                h.total_90d AS TOTAL_90D,
                h.kept_90d AS KEPT_90D,
                h.missed_90d AS MISSED_90D,
                ha.total_all AS TOTAL_ALL,
                ha.kept_all AS KEPT_ALL,
                ha.missed_all AS MISSED_ALL,
                ls.last_status AS LAST_STATUS
            FROM joined rd
            LEFT JOIN history_90d h ON h.person_id = rd.person_id
            LEFT JOIN history_all ha ON ha.person_id = rd.person_id
            LEFT JOIN last_status ls ON ls.person_id = rd.person_id
            WHERE rd.rn = 1
            ORDER BY rd.Location, rd.ACTUAL_END_DATETIME ASC
        `;
    
    connection.execute({
        sqlText: predictionQuery,
        complete: function(err, stmt, rows) {
            if (err) {
                console.error(' Attendance prediction query error:', err);
                console.error(' Query that failed:', predictionQuery);
                res.status(500).json({ error: 'Failed to fetch attendance predictions' });
            } else {
                console.log(` Attendance prediction query returned ${rows.length} rows`);
                
                // Log detailed risk calculation for each row
                rows.forEach((row, idx) => {
                    const total90d = row.TOTAL_90D || 0;
                    const kept90d = row.KEPT_90D || 0;
                    const missed90d = row.MISSED_90D || 0;
                    const totalAll = row.TOTAL_ALL || 0;
                    const keptAll = row.KEPT_ALL || 0;
                    const missedAll = row.MISSED_ALL || 0;
                    
                    // Calculate rates
                    const rate90d = total90d > 0 ? (kept90d / total90d) : null;
                    const rateAll = totalAll > 0 ? (keptAll / totalAll) : null;
                    
                    // Determine which rate is being used
                    const use90d = total90d >= 3;
                    const effectiveRate = use90d ? rate90d : rateAll;
                    const effectiveTotal = use90d ? total90d : totalAll;
                    const effectiveKept = use90d ? kept90d : keptAll;
                    const effectiveMissed = use90d ? missed90d : missedAll;
                    
                    console.log(`\nRisk Calculation for Row ${idx + 1}: ${row.FIRST_NAME} ${row.LAST_NAME} (ID: ${row.PERSON_ID})`);
                    console.log(`  90-Day Stats: ${kept90d} kept, ${missed90d} missed, ${total90d} total → ${rate90d !== null ? (rate90d * 100).toFixed(1) : 'N/A'}%`);
                    console.log(`  All-Time Stats: ${keptAll} kept, ${missedAll} missed, ${totalAll} total → ${rateAll !== null ? (rateAll * 100).toFixed(1) : 'N/A'}%`);
                    console.log(`  Using: ${use90d ? '90-Day' : 'All-Time'} (${total90d >= 3 ? '90d has >= 3 appts' : '90d has < 3 appts, using all-time'})`);
                    console.log(`  Effective Rate: ${effectiveRate !== null ? (effectiveRate * 100).toFixed(2) : 'N/A'}% (${effectiveKept}/${effectiveTotal})`);
                    console.log(`  Risk Level: ${row.RISK_LEVEL}`);
                    console.log(`  Last Status: ${row.LAST_STATUS || 'N/A'}`);
                });
                
                if (rows.length > 0) {
                    console.log('\n Sample prediction row:', JSON.stringify(rows[0], null, 2));
                } else {
                    console.log(' No prediction data found - this might be why you see "Unknown"');
                }
                res.json(rows);
            }
        }
    });
});
*/

// API endpoint to get weekly risk analysis for all scheduled appointments
app.get('/api/weekly-risk-analysis', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log(' Fetching weekly risk analysis...');
    
    console.log(' Query will use DATE_TRUNC week (starts Sunday) for date range');
    console.log('Excluding Error status appointments (matching Dashboard and Clinical Director)');
    
    const weeklyRiskQuery = `
        WITH week_schedule AS (
            -- Get all scheduled appointments for current week (Sunday to Saturday)
            -- Adjust DATE_TRUNC to start on Sunday by subtracting day of week
            SELECT 
                mv_sa.client_id,
                mv_sa.staff_id,
                mv_sa.activity_log_id,
                mv_sa.actual_begin_datetime AS scheduled_datetime,
                TO_DATE(mv_sa.actual_begin_datetime) AS scheduled_date
            FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
            WHERE TO_DATE(mv_sa.actual_begin_datetime) >= DATE_TRUNC('week', CURRENT_DATE()) - INTERVAL '1 day'
              AND TO_DATE(mv_sa.actual_begin_datetime) < DATE_TRUNC('week', CURRENT_DATE()) + INTERVAL '7 days'
        ),
        schedule_with_details AS (
            SELECT
                ws.client_id,
                ws.staff_id,
                ws.activity_log_id,
                ws.scheduled_datetime,
                ws.scheduled_date,
                -- Get day of week number for sorting/grouping
                DAYOFWEEK(ws.scheduled_date) AS day_of_week,
                -- Get day name directly from Snowflake
                DAYNAME(ws.scheduled_date) AS day_name_direct,
                org.name AS location,
                staff.full_name AS staff_name,
                p.person_id,
                p.last_name,
                p.first_name,
                -- Check if appointment was kept
                CASE WHEN ad.status = 'Kept' THEN 'Kept'
                     WHEN ad.status IN ('DNS', 'CBC', 'CBT') THEN 'Missed'
                     ELSE 'Scheduled' END AS appointment_status,
                ad.status AS actual_status,
                ad.actual_begin_datetime,
                ad.actual_end_datetime
            FROM week_schedule ws
            JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = ws.client_id
            JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = ws.staff_id
            JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = ws.activity_log_id
            JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
            LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
              ON ad.activity_log_id = ws.activity_log_id
            LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
            WHERE UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
        ),
        historical_attendance AS (
            -- 90-day attendance history (only completed appointments)
            SELECT
                ad.client_id AS person_id,
                COUNT(*) AS total_90d,
                SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_90d,
                SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_90d,
                ROUND(
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END)::FLOAT / 
                    NULLIF(COUNT(*), 0) * 100, 1
                ) AS attendance_rate_90d
            FROM CARELOGIC_PROD.SECURE.activity_detail ad
            JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
            JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
            WHERE TO_DATE(ad.CHANGED_DATE) >= DATEADD(day, -90, CURRENT_DATE())
              AND TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
              AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
              AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
            GROUP BY ad.client_id
        ),
        all_time_attendance AS (
            -- All-time attendance history (only completed appointments)
            SELECT
                ad.client_id AS person_id,
                COUNT(*) AS total_all,
                SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_all,
                SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_all,
                ROUND(
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END)::FLOAT / 
                    NULLIF(COUNT(*), 0) * 100, 1
                ) AS attendance_rate_all
            FROM CARELOGIC_PROD.SECURE.activity_detail ad
            JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
            JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
            WHERE ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
              AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
            GROUP BY ad.client_id
        ),
        last_appointment_status AS (
            -- Get last appointment status (only completed appointments)
            SELECT 
                person_id, 
                last_status,
                days_since_last_appointment
            FROM (
                SELECT
                    ad.client_id AS person_id,
                    ad.status AS last_status,
                    DATEDIFF(day, TO_DATE(ad.CHANGED_DATE), CURRENT_DATE()) AS days_since_last_appointment,
                    ROW_NUMBER() OVER (
                        PARTITION BY ad.client_id
                        ORDER BY ad.CHANGED_DATE DESC
                    ) AS rn
                FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
                  AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                  AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
            ) s
            WHERE rn = 1
        )
        SELECT 
            MAX(swd.activity_log_id) AS activity_log_id,
            swd.person_id,
            MAX(swd.first_name) AS first_name,
            MAX(swd.last_name) AS last_name,
            MAX(swd.location) AS location,
            swd.staff_id,
            MAX(swd.staff_name) AS staff_name,
            swd.scheduled_datetime,
            swd.scheduled_date,
            swd.day_of_week,
            -- Convert abbreviated day names to full names for frontend compatibility
            CASE MAX(swd.day_name_direct)
                WHEN 'Mon' THEN 'Monday'
                WHEN 'Tue' THEN 'Tuesday'
                WHEN 'Wed' THEN 'Wednesday'
                WHEN 'Thu' THEN 'Thursday'
                WHEN 'Fri' THEN 'Friday'
                WHEN 'Sat' THEN 'Saturday'
                WHEN 'Sun' THEN 'Sunday'
                ELSE MAX(swd.day_name_direct)
            END AS day_name,
            MAX(swd.appointment_status) AS appointment_status,
            MAX(swd.actual_status) AS actual_status,
            
            -- Use 90-day attendance if >= 3 appointments, otherwise all-time
            MAX(CASE 
                WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                ELSE COALESCE(a.attendance_rate_all, 0)
            END) AS effective_attendance_rate,
            
            -- Risk score (0-100, higher = more likely to attend)
            MAX(CASE 
                WHEN (h.total_90d IS NULL OR h.total_90d = 0) AND (a.total_all IS NULL OR a.total_all = 0) THEN 50
                WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                ELSE COALESCE(a.attendance_rate_all, 50)
            END) AS risk_score,
            
            -- Risk level (based purely on attendance percentage)
            MAX(CASE 
                WHEN (h.total_90d IS NULL OR h.total_90d = 0) AND (a.total_all IS NULL OR a.total_all = 0) THEN 'Unknown'
                WHEN (
                    CASE 
                        WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                        ELSE COALESCE(a.attendance_rate_all, 0)
                    END
                ) < 50 THEN 'High'
                WHEN (
                    CASE 
                        WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                        ELSE COALESCE(a.attendance_rate_all, 0)
                    END
                ) < 80 THEN 'Medium'
                ELSE 'Low'
            END) AS risk_level,
            
            -- Historical data for context
            MAX(h.total_90d) AS total_90d,
            MAX(h.kept_90d) AS kept_90d,
            MAX(h.missed_90d) AS missed_90d,
            MAX(a.total_all) AS total_all,
            MAX(a.kept_all) AS kept_all,
            MAX(a.missed_all) AS missed_all,
            MAX(COALESCE(ls.last_status, 'Unknown')) AS last_status,
            MAX(COALESCE(ls.days_since_last_appointment, 999)) AS days_since_last_appointment,
            
            -- Time-based risk factors
            MAX(CASE WHEN EXTRACT(HOUR FROM swd.scheduled_datetime) < 9 THEN 'Early'
                 WHEN EXTRACT(HOUR FROM swd.scheduled_datetime) > 16 THEN 'Late'
                 ELSE 'Normal' END) AS time_period,
                 
            MAX(CASE WHEN swd.day_of_week IN (0, 6) THEN 'Weekend'
                 ELSE 'Weekday' END) AS day_type
                 
        FROM schedule_with_details swd
        LEFT JOIN (
            SELECT person_id, total_90d, kept_90d, missed_90d, attendance_rate_90d
            FROM historical_attendance
        ) h ON h.person_id = swd.person_id
        LEFT JOIN (
            SELECT person_id, total_all, kept_all, missed_all, attendance_rate_all
            FROM all_time_attendance
        ) a ON a.person_id = swd.person_id
        LEFT JOIN (
            SELECT person_id, last_status, days_since_last_appointment
            FROM last_appointment_status
        ) ls ON ls.person_id = swd.person_id
        WHERE COALESCE(swd.actual_status, '') != 'Error'
        GROUP BY 
            swd.activity_log_id,
            swd.person_id,
            swd.staff_id,
            swd.scheduled_datetime,
            swd.scheduled_date,
            swd.day_of_week,
            swd.location,
            swd.staff_name,
            swd.first_name,
            swd.last_name,
            swd.day_name_direct,
            swd.appointment_status,
            swd.actual_status,
            h.total_90d,
            h.kept_90d,
            h.missed_90d,
            h.attendance_rate_90d,
            a.total_all,
            a.kept_all,
            a.missed_all,
            a.attendance_rate_all,
            ls.last_status,
            ls.days_since_last_appointment
        ORDER BY 
            swd.scheduled_date ASC,
            swd.scheduled_datetime ASC
    `;
    
    executeSnowflakeQuery(weeklyRiskQuery, {
        onSuccess: (rows, res) => {
            console.log(` Weekly risk analysis returned ${rows.length} appointments (excluding Error status)`);
            if (rows.length > 0) {
                    console.log(' Sample weekly risk row:', JSON.stringify(rows[0], null, 2));
                    
                    // Check date range returned
                    const dates = [...new Set(rows.map(r => r.SCHEDULED_DATE))].sort();
                    console.log(' Date range in weekly-risk data:', JSON.stringify({
                        firstDate: dates[0],
                        lastDate: dates[dates.length - 1],
                        totalDays: dates.length
                    }));
                    
                    // Count by date
                    const byDate = rows.reduce((acc, row) => {
                        const date = row.SCHEDULED_DATE;
                        acc[date] = (acc[date] || 0) + 1;
                        return acc;
                    }, {});
                    console.log(' WEEKLY-RISK ENDPOINT - Appointments by date:', JSON.stringify(byDate));
                    
                    // Check for duplicate activity_log_ids - check what format dates are in
                    console.log('Sample SCHEDULED_DATE values:', rows.slice(0, 3).map(r => ({
                        date: r.SCHEDULED_DATE,
                        type: typeof r.SCHEDULED_DATE,
                        iso: r.SCHEDULED_DATE instanceof Date ? r.SCHEDULED_DATE.toISOString() : 'not a date'
                    })));
                    
                    // Check Oct 21 count using local date (not UTC)
                    const oct21Rows = rows.filter(r => {
                        if (r.SCHEDULED_DATE instanceof Date) {
                            const d = r.SCHEDULED_DATE;
                            const year = d.getFullYear();
                            const month = String(d.getMonth() + 1).padStart(2, '0');
                            const day = String(d.getDate()).padStart(2, '0');
                            const localDateStr = `${year}-${month}-${day}`;
                            return localDateStr === '2025-10-21';
                        }
                        return String(r.SCHEDULED_DATE).includes('2025-10-21');
                    });
                    const uniqueActivityLogs = new Set(oct21Rows.map(r => r.ACTIVITY_LOG_ID)).size;
                    console.log(`WEEKLY-RISK - Oct 21 (local time): ${oct21Rows.length} rows, ${uniqueActivityLogs} unique activity_log_ids`);
                    console.log(` Converting ${rows.length} Date objects to 'YYYY-MM-DD' strings (using local date, NOT UTC)`);
                    
                    // Log detailed risk calculation for a sample of rows (first 5, plus any with High risk)
                    const highRiskRows = rows.filter(r => r.risk_level === 'High' || r.RISK_LEVEL === 'High');
                    const sampleRows = [...rows.slice(0, 5), ...highRiskRows.slice(0, 3)].filter((v, i, a) => a.findIndex(r => r.person_id === v.person_id) === i);
                    
                    console.log('\nDetailed Risk Calculations (Sample):');
                    sampleRows.forEach((row, idx) => {
                        const total90d = row.total_90d || 0;
                        const kept90d = row.kept_90d || 0;
                        const missed90d = row.missed_90d || 0;
                        const totalAll = row.total_all || 0;
                        const keptAll = row.kept_all || 0;
                        const missedAll = row.missed_all || 0;
                        const riskLevel = row.risk_level || row.RISK_LEVEL || 'Unknown';
                        
                        // Calculate rates
                        const rate90d = total90d > 0 ? (kept90d / total90d) : null;
                        const rateAll = totalAll > 0 ? (keptAll / totalAll) : null;
                        const use90d = total90d >= 3;
                        const effectiveRate = use90d ? rate90d : rateAll;
                        
                        console.log(`\n  Client: ${row.first_name} ${row.last_name} (ID: ${row.person_id})`);
                        console.log(`    90-Day: ${kept90d} kept, ${missed90d} missed, ${total90d} total → ${rate90d !== null ? (rate90d * 100).toFixed(1) : 'N/A'}%`);
                        console.log(`    All-Time: ${keptAll} kept, ${missedAll} missed, ${totalAll} total → ${rateAll !== null ? (rateAll * 100).toFixed(1) : 'N/A'}%`);
                        console.log(`    Using: ${use90d ? '90-Day' : 'All-Time'} → Effective Rate: ${effectiveRate !== null ? (effectiveRate * 100).toFixed(2) : 'N/A'}%`);
                        console.log(`    Risk Level: ${riskLevel}`);
                        console.log(`    Next Appointment: ${row.SCHEDULED_DATE} (${row.DAY_NAME || 'N/A'})`);
                    });
                    
                    // Add summary statistics
                    const summary = {
                        total_appointments: rows.length,
                        high_risk: rows.filter(r => r.RISK_LEVEL === 'High' || r.risk_level === 'High').length,
                        medium_risk: rows.filter(r => r.RISK_LEVEL === 'Medium' || r.risk_level === 'Medium').length,
                        low_risk: rows.filter(r => r.RISK_LEVEL === 'Low' || r.risk_level === 'Low').length,
                        unknown_risk: rows.filter(r => (r.RISK_LEVEL === 'Unknown' || r.risk_level === 'Unknown')).length,
                        by_day: rows.reduce((acc, row) => {
                            const day = row.DAY_NAME;
                            acc[day] = (acc[day] || 0) + 1;
                            return acc;
                        }, {}),
                        by_location: rows.reduce((acc, row) => {
                            const loc = row.LOCATION;
                            acc[loc] = (acc[loc] || 0) + 1;
                            return acc;
                        }, {})
                    };
                    
                    console.log('\n Risk Summary:', summary);
                    
                    // Convert Date objects to ISO date strings for frontend compatibility
                    // IMPORTANT: Use local date, not UTC, to avoid timezone shifts
                    const convertedRows = rows.map(row => {
                        let dateStr = row.SCHEDULED_DATE;
                        if (row.SCHEDULED_DATE instanceof Date) {
                            const d = row.SCHEDULED_DATE;
                            const year = d.getFullYear();
                            const month = String(d.getMonth() + 1).padStart(2, '0');
                            const day = String(d.getDate()).padStart(2, '0');
                            dateStr = `${year}-${month}-${day}`;
                        }
                        return {
                            ...row,
                            SCHEDULED_DATE: dateStr
                        };
                    });
                    
                    // Log date breakdown after conversion
                    const dateBreakdown = convertedRows.reduce((acc, row) => {
                        acc[row.SCHEDULED_DATE] = (acc[row.SCHEDULED_DATE] || 0) + 1;
                        return acc;
                    }, {});
                    console.log(' WEEKLY-RISK - Date breakdown after conversion:', JSON.stringify(dateBreakdown, null, 2));
                    
                    // Log day name mapping to verify timezone fix
                    const dayBreakdown = convertedRows.reduce((acc, row) => {
                        const key = `${row.SCHEDULED_DATE} (${row.DAY_NAME})`;
                        acc[key] = (acc[key] || 0) + 1;
                        return acc;
                    }, {});
                    console.log(' WEEKLY-RISK - Date + Day name breakdown:', JSON.stringify(dayBreakdown, null, 2));
                    
                    // Debug: Check what DAY_OF_WEEK values we're getting
                    const dayOfWeekSample = convertedRows.slice(0, 5).map(r => ({
                        date: r.SCHEDULED_DATE,
                        dayName: r.DAY_NAME,
                        dayOfWeek: r.DAY_OF_WEEK
                    }));
                    console.log('DAY_OF_WEEK sample values:', JSON.stringify(dayOfWeekSample, null, 2));
                    
                    // Debug: Check appointment statuses for all dates
                    const allDates = [...new Set(convertedRows.map(r => r.SCHEDULED_DATE))].sort();
                    const statusByDate = {};
                    allDates.forEach(date => {
                        const dateRows = convertedRows.filter(r => r.SCHEDULED_DATE === date);
                        const breakdown = dateRows.reduce((acc, r) => {
                            const status = r.APPOINTMENT_STATUS || 'null';
                            acc[status] = (acc[status] || 0) + 1;
                            return acc;
                        }, {});
                        statusByDate[date] = breakdown;
                    });
                    console.log(` APPOINTMENT_STATUS breakdown by date:`, JSON.stringify(statusByDate, null, 2));
                    
                    res.json({
                        appointments: convertedRows,
                        summary: summary,
                        generated_at: new Date().toISOString()
                    });
                } else {
                    console.log(' No weekly appointments found');
                    res.json({
                        appointments: [],
                        summary: {
                            total_appointments: 0,
                            high_risk: 0,
                            medium_risk: 0,
                            low_risk: 0,
                            unknown_risk: 0
                        },
                        generated_at: new Date().toISOString()
                    });
                }
        }
    }, res, 'Failed to fetch weekly risk analysis');
});

// REMOVED: Duplicate pathway-coordinator endpoint - already defined above with middleware

// Staff Performance endpoint (30 days of data for Staff Performance)
app.get('/api/staff-performance', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log(' Fetching staff performance data (30 days)...');
    
    const staffPerformanceQuery = `
        SELECT 
            TO_DATE(mv_sa.actual_begin_datetime) AS scheduled_date,
            org.name AS location,
            staff.full_name AS staff_name,
            p.person_id,
            p.last_name,
            p.first_name,
            COALESCE(ad.status, 'Scheduled') AS appointment_status,
            ad.status AS actual_status
        FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
        JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = mv_sa.client_id
        JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = mv_sa.staff_id
        JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = mv_sa.activity_log_id
        JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
        LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad ON ad.activity_log_id = mv_sa.activity_log_id
        JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
        WHERE TO_DATE(mv_sa.actual_begin_datetime) >= DATEADD(day, -30, CURRENT_DATE())
          AND TO_DATE(mv_sa.actual_begin_datetime) < CURRENT_DATE()
          AND UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
          AND COALESCE(ad.status, 'Scheduled') != 'Error'
        ORDER BY scheduled_date DESC, staff_name ASC;
    `;
    
        executeSnowflakeQuery(staffPerformanceQuery, {
            onSuccess: (rows, res) => {
                console.log(` Staff Performance query returned ${rows.length} rows`);
                res.json(rows);
            }
        }, res, 'Failed to fetch staff performance data');
});

// Clinical Director (today-only schedule view, excluding Error status)
app.get('/api/clinical-director', requireAuth, requireSnowflakeReady, (req, res) => {
    
    try {
        const sql = generateSQLQuery('today', 'clinical-director');
        executeSnowflakeQuery(sql, {
            onSuccess: (rows, res) => {
                const converted = rows.map(r => ({
                    ...r,
                    ACTUAL_END_DATETIME: toESTString(r.ACTUAL_END_DATETIME)
                }));
                res.json(converted);
            }
        }, res, 'Failed to fetch clinical director data');
    } catch (e) {
        console.error('Clinical Director handler error:', e);
        errorResponses.serverError(res, 'Failed to fetch clinical director data', e.message);
    }
});

// Unified Dashboard Data Endpoint - Single source of truth for all dashboard data
let dashboardCache = null;
let dashboardCacheTime = 0;
const DASHBOARD_CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

app.get('/api/dashboard-data', requireAuth, async (req, res) => {
    console.log(' Fetching unified dashboard data...');
    console.log(' Query params:', JSON.stringify(req.query));
    
    // Check if Snowflake is ready
    if (!snowflakeReady) {
        console.error(' Snowflake connection not ready');
        // Return cached data if available, otherwise return error
        if (dashboardCache) {
            console.log(' Returning stale cached data (Snowflake not ready)');
            return res.json(dashboardCache);
        }
        return res.status(503).json({ 
            error: 'Database connection not ready. Please try again in a moment.',
            snowflakeReady: false
        });
    }
    
    // Check if we have valid cached data (unless force_refresh is requested)
    const now = Date.now();
    const forceRefresh = req.query.force_refresh === 'true';
    if (dashboardCache && (now - dashboardCacheTime) < DASHBOARD_CACHE_DURATION && !forceRefresh) {
        console.log(' Returning cached dashboard data (cache age:', Math.round((now - dashboardCacheTime) / 1000), 'seconds)');
        console.log(' To see fresh data with logging, add ?force_refresh=true to the URL');
        return res.json(dashboardCache);
    }
    
    console.log(' Cache expired or force refresh requested, fetching fresh dashboard data...');
    
    try {
        // Get today's appointments from clinical-director query
        const todayQuery = generateSQLQuery('today', 'clinical-director');
        
        // Get weekly risk data
        const weeklyRiskQuery = `
            WITH week_schedule AS (
                SELECT 
                    mv_sa.client_id,
                    mv_sa.staff_id,
                    mv_sa.activity_log_id,
                    mv_sa.actual_begin_datetime AS scheduled_datetime,
                    TO_DATE(mv_sa.actual_begin_datetime) AS scheduled_date
                FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
                WHERE TO_DATE(mv_sa.actual_begin_datetime) >= DATE_TRUNC('week', CURRENT_DATE()) - INTERVAL '1 day'
                  AND TO_DATE(mv_sa.actual_begin_datetime) < DATE_TRUNC('week', CURRENT_DATE()) + INTERVAL '7 days'
            ),
            schedule_with_details AS (
                SELECT
                    ws.client_id,
                    ws.staff_id,
                    ws.activity_log_id,
                    ws.scheduled_datetime,
                    ws.scheduled_date,
                    DAYOFWEEK(ws.scheduled_date) AS day_of_week,
                    DAYNAME(ws.scheduled_date) AS day_name_direct,
                    org.name AS location,
                    staff.full_name AS staff_name,
                    p.person_id,
                    p.last_name,
                    p.first_name,
                    CASE WHEN ad.status = 'Kept' THEN 'Kept'
                         WHEN ad.status IN ('DNS', 'CBC', 'CBT') THEN 'Missed'
                         ELSE 'Scheduled' END AS appointment_status,
                    ad.status AS actual_status,
                    ad.actual_begin_datetime,
                    ad.actual_end_datetime
                FROM week_schedule ws
                JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = ws.client_id
                JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = ws.staff_id
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = ws.activity_log_id
                JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
                LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
                  ON ad.activity_log_id = ws.activity_log_id
                LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
            ),
            historical_attendance AS (
                SELECT
                    ad.client_id AS person_id,
                    COUNT(*) AS total_90d,
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_90d,
                    SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_90d,
                    ROUND(
                        SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END)::FLOAT / 
                        NULLIF(COUNT(*), 0) * 100, 1
                    ) AS attendance_rate_90d
                FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE TO_DATE(ad.CHANGED_DATE) >= DATEADD(day, -90, CURRENT_DATE())
                  AND TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
                  AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                  AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                GROUP BY ad.client_id
            ),
            all_time_attendance AS (
                SELECT
                    ad.client_id AS person_id,
                    COUNT(*) AS total_all,
                    SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END) AS kept_all,
                    SUM(CASE WHEN ad.status IN ('DNS','CBC','CBT') THEN 1 ELSE 0 END) AS missed_all,
                    ROUND(
                        SUM(CASE WHEN ad.status = 'Kept' THEN 1 ELSE 0 END)::FLOAT / 
                        NULLIF(COUNT(*), 0) * 100, 1
                    ) AS attendance_rate_all
                FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                WHERE ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                  AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                GROUP BY ad.client_id
            ),
            last_appointment_status AS (
                SELECT 
                    person_id, 
                    last_status,
                    days_since_last_appointment
                FROM (
                    SELECT
                        ad.client_id AS person_id,
                        ad.status AS last_status,
                        DATEDIFF(day, TO_DATE(ad.CHANGED_DATE), CURRENT_DATE()) AS days_since_last_appointment,
                        ROW_NUMBER() OVER (
                            PARTITION BY ad.client_id
                            ORDER BY ad.CHANGED_DATE DESC
                        ) AS rn
                    FROM CARELOGIC_PROD.SECURE.activity_detail ad
                    JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                    JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
                    WHERE TO_DATE(ad.CHANGED_DATE) <= CURRENT_DATE()
                      AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                      AND UPPER(act.description) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
                ) s
                WHERE rn = 1
            )
            SELECT 
                MAX(swd.activity_log_id) AS activity_log_id,
                swd.person_id,
                MAX(swd.first_name) AS first_name,
                MAX(swd.last_name) AS last_name,
                MAX(swd.location) AS location,
                swd.staff_id,
                MAX(swd.staff_name) AS staff_name,
                swd.scheduled_datetime,
                swd.scheduled_date,
                swd.day_of_week,
                CASE MAX(swd.day_name_direct)
                    WHEN 'Mon' THEN 'Monday'
                    WHEN 'Tue' THEN 'Tuesday'
                    WHEN 'Wed' THEN 'Wednesday'
                    WHEN 'Thu' THEN 'Thursday'
                    WHEN 'Fri' THEN 'Friday'
                    WHEN 'Sat' THEN 'Saturday'
                    WHEN 'Sun' THEN 'Sunday'
                    ELSE MAX(swd.day_name_direct)
                END AS day_name,
                MAX(swd.appointment_status) AS appointment_status,
                MAX(swd.actual_status) AS actual_status,
                MAX(CASE 
                    WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                    ELSE COALESCE(a.attendance_rate_all, 0)
                END) AS effective_attendance_rate,
                MAX(CASE 
                    WHEN (h.total_90d IS NULL OR h.total_90d = 0) AND (a.total_all IS NULL OR a.total_all = 0) THEN 'Unknown'
                    WHEN (
                        CASE 
                            WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                            ELSE COALESCE(a.attendance_rate_all, 0)
                        END
                    ) < 50 THEN 'High'
                    WHEN (
                        CASE 
                            WHEN h.total_90d >= 3 THEN h.attendance_rate_90d
                            ELSE COALESCE(a.attendance_rate_all, 0)
                        END
                    ) < 80 THEN 'Medium'
                    ELSE 'Low'
                END) AS risk_level,
                MAX(h.total_90d) AS total_90d,
                MAX(h.kept_90d) AS kept_90d,
                MAX(h.missed_90d) AS missed_90d,
                MAX(a.total_all) AS total_all,
                MAX(a.kept_all) AS kept_all,
                MAX(a.missed_all) AS missed_all,
                MAX(COALESCE(ls.last_status, 'Unknown')) AS last_status,
                MAX(COALESCE(ls.days_since_last_appointment, 999)) AS days_since_last_appointment
            FROM schedule_with_details swd
            LEFT JOIN (
                SELECT person_id, total_90d, kept_90d, missed_90d, attendance_rate_90d
                FROM historical_attendance
            ) h ON h.person_id = swd.person_id
            LEFT JOIN (
                SELECT person_id, total_all, kept_all, missed_all, attendance_rate_all
                FROM all_time_attendance
            ) a ON a.person_id = swd.person_id
            LEFT JOIN (
                SELECT person_id, last_status, days_since_last_appointment
                FROM last_appointment_status
            ) ls ON ls.person_id = swd.person_id
            WHERE COALESCE(swd.actual_status, '') != 'Error'
            GROUP BY 
                swd.activity_log_id,
                swd.person_id,
                swd.staff_id,
                swd.scheduled_datetime,
                swd.scheduled_date,
                swd.day_of_week,
                swd.location,
                swd.staff_name,
                swd.first_name,
                swd.last_name,
                swd.day_name_direct,
                swd.appointment_status,
                swd.actual_status,
                h.total_90d,
                h.kept_90d,
                h.missed_90d,
                h.attendance_rate_90d,
                a.total_all,
                a.kept_all,
                a.missed_all,
                a.attendance_rate_all,
                ls.last_status,
                ls.days_since_last_appointment
            ORDER BY 
                swd.scheduled_date ASC,
                swd.scheduled_datetime ASC
        `;
        
        // Execute both queries in parallel
        const [todayData, weeklyData] = await Promise.all([
            new Promise((resolve, reject) => {
                connection.execute({
                    sqlText: todayQuery,
                    complete: function(err, stmt, rows) {
                        if (err) reject(err);
                        else resolve(rows || []);
                    }
                });
            }),
            new Promise((resolve, reject) => {
                connection.execute({
                    sqlText: weeklyRiskQuery,
                    complete: function(err, stmt, rows) {
                        if (err) {
                            console.error(' Weekly risk query error:', err);
                            reject(err);
                        } else {
                            console.log(` Weekly risk query returned ${rows.length} rows`);
                            
                            // Log detailed risk calculation for a sample of rows (first 5, plus any with High risk)
                            const highRiskRows = rows.filter(r => r.risk_level === 'High' || r.RISK_LEVEL === 'High');
                            const sampleRows = [...rows.slice(0, 5), ...highRiskRows.slice(0, 3)].filter((v, i, a) => {
                                const id = v.PERSON_ID || v.person_id;
                                return a.findIndex(r => (r.PERSON_ID || r.person_id) === id) === i;
                            });
                            
                            console.log('\nDASHBOARD-DATA: Detailed Risk Calculations (Sample):');
                            sampleRows.forEach((row, idx) => {
                                const total90d = row.total_90d || row.TOTAL_90D || 0;
                                const kept90d = row.kept_90d || row.KEPT_90D || 0;
                                const missed90d = row.missed_90d || row.MISSED_90D || 0;
                                const totalAll = row.total_all || row.TOTAL_ALL || 0;
                                const keptAll = row.kept_all || row.KEPT_ALL || 0;
                                const missedAll = row.missed_all || row.MISSED_ALL || 0;
                                const riskLevel = row.risk_level || row.RISK_LEVEL || 'Unknown';
                                const firstName = row.first_name || row.FIRST_NAME || 'Unknown';
                                const lastName = row.last_name || row.LAST_NAME || 'Unknown';
                                const personId = row.person_id || row.PERSON_ID || 'Unknown';
                                
                                // Calculate rates
                                const rate90d = total90d > 0 ? (kept90d / total90d) : null;
                                const rateAll = totalAll > 0 ? (keptAll / totalAll) : null;
                                const use90d = total90d >= 3;
                                const effectiveRate = use90d ? rate90d : rateAll;
                                
                                console.log(`\n  Client: ${firstName} ${lastName} (ID: ${personId})`);
                                console.log(`    90-Day: ${kept90d} kept, ${missed90d} missed, ${total90d} total → ${rate90d !== null ? (rate90d * 100).toFixed(1) : 'N/A'}%`);
                                console.log(`    All-Time: ${keptAll} kept, ${missedAll} missed, ${totalAll} total → ${rateAll !== null ? (rateAll * 100).toFixed(1) : 'N/A'}%`);
                                console.log(`    Using: ${use90d ? '90-Day' : 'All-Time'} → Effective Rate: ${effectiveRate !== null ? (effectiveRate * 100).toFixed(2) : 'N/A'}%`);
                                console.log(`    Risk Level: ${riskLevel}`);
                            });
                            
                            // Also log summary stats
                            const riskSummary = {
                                high: rows.filter(r => r.RISK_LEVEL === 'High' || r.risk_level === 'High').length,
                                medium: rows.filter(r => r.RISK_LEVEL === 'Medium' || r.risk_level === 'Medium').length,
                                low: rows.filter(r => r.RISK_LEVEL === 'Low' || r.risk_level === 'Low').length,
                                unknown: rows.filter(r => (r.RISK_LEVEL === 'Unknown' || r.risk_level === 'Unknown')).length
                            };
                            console.log('\n DASHBOARD-DATA: Risk Summary:', riskSummary);
                            
                            resolve(rows || []);
                        }
                    }
                });
            })
        ]);
        
        console.log(` Today data: ${todayData.length} appointments`);
        console.log(` Weekly data: ${weeklyData.length} appointments`);
        
        // Process today's data
        const todayStr = new Date().toISOString().split('T')[0];
        const todayAppointments = todayData.filter(appt => {
            const apptDate = appt.ACTUAL_END_DATETIME ? 
                new Date(appt.ACTUAL_END_DATETIME).toISOString().split('T')[0] : 
                todayStr;
            return apptDate === todayStr;
        });
        
        const todayKept = todayAppointments.filter(appt => 
            appt.APPOINTMENT_STATUS === 'Kept' || appt.appointment_status === 'Kept'
        ).length;
        
        const todayDnsMissed = todayAppointments.filter(appt => 
            appt.APPOINTMENT_STATUS === 'DNS' || appt.APPOINTMENT_STATUS === 'CBC' || appt.APPOINTMENT_STATUS === 'CBT' ||
            appt.appointment_status === 'DNS' || appt.appointment_status === 'CBC' || appt.appointment_status === 'CBT'
        ).length;
        
        // Process weekly data for risk breakdown
        const weekStartStr = new Date();
        const dayOfWeek = weekStartStr.getDay();
        weekStartStr.setDate(weekStartStr.getDate() - dayOfWeek);
        const weekStart = weekStartStr.toISOString().split('T')[0];
        
        const weekToDateAppointments = weeklyData.filter(appt => {
            const apptDate = appt.SCHEDULED_DATE || appt.scheduled_date;
            return apptDate >= weekStart && apptDate <= todayStr;
        });
        
        const weekToDateKept = weekToDateAppointments.filter(appt => 
            appt.APPOINTMENT_STATUS === 'Kept' || appt.appointment_status === 'Kept'
        ).length;
        
        const weekToDateLocations = new Set(weekToDateAppointments.map(appt => 
            appt.LOCATION || appt.location
        )).size;
        
        // Process risk breakdown for the full week (not just today)
        const riskBreakdown = {
            high: weeklyData.filter(appt => 
                appt.RISK_LEVEL === 'High' || appt.risk_level === 'High'
            ).length,
            medium: weeklyData.filter(appt => 
                appt.RISK_LEVEL === 'Medium' || appt.risk_level === 'Medium'
            ).length,
            low: weeklyData.filter(appt => 
                appt.RISK_LEVEL === 'Low' || appt.risk_level === 'Low'
            ).length
        };
        
        // Process today's risk breakdown for "Needs Attention" section
        // Use Clinical Director data (todayData) instead of filtering weekly data
        // This gives us the correct count of today's appointments (1,001)
        
        // Create a lookup map for risk levels from weekly data
        const riskLevelMap = new Map();
        weeklyData.forEach(appt => {
            const key = `${appt.PERSON_ID || appt.person_id}_${appt.STAFF_ID || appt.staff_id}`;
            riskLevelMap.set(key, appt.RISK_LEVEL || appt.risk_level);
        });
        
        const todayRiskData = todayData.map(appt => {
            // Look up risk level from weekly data using person_id and staff_id
            const key = `${appt.PERSON_ID || appt.person_id}_${appt.STAFF_ID || appt.staff_id}`;
            const riskLevel = riskLevelMap.get(key) || 'Unknown';
            
            // Map Clinical Director data to match weekly risk data structure
            return {
                ...appt,
                SCHEDULED_DATETIME: appt.ACTUAL_END_DATETIME,
                RISK_LEVEL: riskLevel
            };
        });
        
        console.log('Today risk calculation debug:', JSON.stringify({
            todayStr: todayStr,
            clinicalDirectorData: todayData.length,
            weeklyRiskData: weeklyData.length,
            todayRiskDataCount: todayRiskData.length,
            riskLevelMapSize: riskLevelMap.size,
            sampleTodayData: todayRiskData.slice(0, 3).map(appt => ({
                person_id: appt.PERSON_ID,
                staff_id: appt.STAFF_ID,
                risk_level: appt.RISK_LEVEL,
                actual_end_datetime: appt.ACTUAL_END_DATETIME
            })),
            todayHighRiskCount: todayRiskData.filter(appt => 
                appt.RISK_LEVEL === 'High'
            ).length
        }, null, 2));
        
        const todayRiskBreakdown = {
            high: todayRiskData.filter(appt => 
                appt.RISK_LEVEL === 'High'
            ).length,
            medium: todayRiskData.filter(appt => 
                appt.RISK_LEVEL === 'Medium'
            ).length,
            low: todayRiskData.filter(appt => 
                appt.RISK_LEVEL === 'Low'
            ).length
        };
        
        console.log('Risk breakdown debug:', JSON.stringify({
            totalWeeklyData: weeklyData.length,
            highRisk: riskBreakdown.high,
            mediumRisk: riskBreakdown.medium,
            lowRisk: riskBreakdown.low,
            sampleHighRisk: weeklyData.filter(appt => 
                appt.RISK_LEVEL === 'High' || appt.risk_level === 'High'
            ).slice(0, 3).map(appt => ({
                client_id: appt.CLIENT_ID || appt.client_id,
                risk_level: appt.RISK_LEVEL || appt.risk_level,
                scheduled_date: appt.SCHEDULED_DATE || appt.scheduled_date
            }))
        }, null, 2));
        
        // Get pathway data (simplified for now)
        const pathwayQuery = generateSQLQuery('today', 'kept-sessions');
        const pathwayData = await new Promise((resolve, reject) => {
            connection.execute({
                sqlText: pathwayQuery,
                complete: function(err, stmt, rows) {
                    if (err) reject(err);
                    else resolve(rows || []);
                }
            });
        });
        
        const pathwaysCreated = pathwayData.filter(p => 
            p.PATHWAYSTATUS === 'Created' || p.pathwayStatus === 'Created'
        ).length;
        
        const pathwaysNotCreated = pathwayData.filter(p => 
            p.PATHWAYSTATUS !== 'Created' && p.pathwayStatus !== 'Created'
        ).length;
        
        // Get Medicaid data (full data, not just count)
        const expiringMedicaidQuery = `
            WITH Latest_HH AS (
                SELECT 
                    client_id, 
                    med_end_date, 
                    enrolled_CMA_name, 
                    end_date, 
                    ROW_NUMBER() OVER (PARTITION BY client_id ORDER BY chg_datetime DESC) AS rn
                FROM Health_Homes
            )
            SELECT 
                sa.staff_name AS StaffName,
                sa.organization AS Location,
                CONVERT(VARCHAR, sa.service_date, 101) AS ServiceDate,
                LTRIM(STUFF(RIGHT(CONVERT(VARCHAR(19), sa.scheduled_begin_datetime, 0), 7), 6, 0, ' ')) AS BeginTime,
                LTRIM(STUFF(RIGHT(CONVERT(VARCHAR(19), sa.scheduled_end_datetime, 0), 7), 6, 0, ' ')) AS EndTime,
                sa.activity_code AS ActivityCode,
                sa.CLIENT_ID AS ClientID,
                sa.CLIENT_NAME AS ClientName,
                sa.PROGRAM_CODE AS ProgramCode,
                CONVERT(VARCHAR, hh.med_end_date, 101) AS MedicaidEndDate,
                hh.enrolled_CMA_name AS HealthHomeEnrolled,
                CONVERT(VARCHAR, hh.end_date, 101) AS HHEndDate,
                (
                    SELECT CONVERT(VARCHAR, MIN(service_date), 101) 
                    FROM mv_scheduled_activities
                    WHERE client_id = sa.client_id
                    AND service_date >= GETDATE()
                    AND activity_code IN ('CCB-TCM','CCB-TCMTH')
                    AND status = 'None'
                    AND last_operation <> 'del'
                ) AS NextTCMAppointment
            FROM mv_SCHEDULED_ACTIVITIES sa
            INNER JOIN Latest_HH hh ON hh.client_id = sa.client_id AND hh.rn = 1
            WHERE sa.TYPE = 'Client'
            AND sa.STATUS = 'None'
            AND sa.service_date >= DATEADD(DD, 1, GETDATE()) 
            AND sa.service_date <= DATEADD(DD, 14, GETDATE())
            AND (
                hh.med_end_date <= DATEADD(DAY, 45, GETDATE())
                OR hh.med_end_date < GETDATE()
            )
        `;
        
        const medicaidData = await new Promise(async (resolve, reject) => {
            try {
                const pool = await sql.connect({
                    server: 'IDCC-FB-SQL',
                    database: 'Carelogic',
                    user: 'sa',
                    password: 'Nycems1234$',
                    options: {
                        encrypt: false,
                        trustServerCertificate: true
                    }
                });
                
                console.log('Connected to SQL Server for Medicaid query');
                
                const result = await pool.request().query(expiringMedicaidQuery);
                console.log(`Medicaid query returned ${result.recordset.length} rows`);
                
                await pool.close();
                resolve(result.recordset || []);
            } catch (err) {
                console.error('Medicaid query error:', err);
                resolve([]);
            }
        });
        
        // Process Medicaid data breakdown
        const today = new Date();
        let medicaidExpired = 0;
        let medicaid0to15 = 0;
        let medicaid16to30 = 0;
        let medicaid31to45 = 0;
        let medicaidWithoutTCM = 0;
        
        for (const record of medicaidData) {
            const endDate = new Date(record.MedicaidEndDate);
            const diffDays = Math.ceil((endDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));
            
            if (diffDays < 0) {
                medicaidExpired++;
            } else if (diffDays <= 15) {
                medicaid0to15++;
            } else if (diffDays <= 30) {
                medicaid16to30++;
            } else if (diffDays <= 45) {
                medicaid31to45++;
            }
            
            // Check for TCM (simplified - you may need to adjust this logic)
            if (!record.NextTCMAppointment || record.NextTCMAppointment.trim() === '') {
                medicaidWithoutTCM++;
            }
        }
        
        const medicaidBreakdown = {
            total: medicaidData.length,
            expired: medicaidExpired,
            days0to15: medicaid0to15,
            days16to30: medicaid16to30,
            days31to45: medicaid31to45,
            withoutTCM: medicaidWithoutTCM
        };
        
        // Build unified response
        const dashboardData = {
            todayStats: {
                totalAppointments: todayAppointments.length,
                keptAppointments: todayKept,
                dnsMissed: todayDnsMissed,
                pathwaysCreated: pathwaysCreated,
                pathwaysNotCreated: pathwaysNotCreated,
                keptRate: todayAppointments.length > 0 ? Math.round((todayKept / todayAppointments.length) * 100) : 0
            },
            riskBreakdown: {
                highRisk: riskBreakdown.high,
                mediumRisk: riskBreakdown.medium,
                lowRisk: riskBreakdown.low,
                total: riskBreakdown.high + riskBreakdown.medium + riskBreakdown.low
            },
            todayRiskBreakdown: {
                highRisk: todayRiskBreakdown.high,
                mediumRisk: todayRiskBreakdown.medium,
                lowRisk: todayRiskBreakdown.low,
                total: todayRiskBreakdown.high + todayRiskBreakdown.medium + todayRiskBreakdown.low
            },
            weekStats: {
                weekToDateTotal: weekToDateAppointments.length,
                weekToDateKept: weekToDateKept,
                weekToDateLocations: weekToDateLocations,
                weekToDateAttendance: weekToDateAppointments.length > 0 ? Math.round((weekToDateKept / weekToDateAppointments.length) * 100) : 0
            },
            medicaidExpiring: medicaidBreakdown.expired,
            medicaidBreakdown: {
                total: medicaidBreakdown.total,
                expired: medicaidBreakdown.expired,
                days0to15: medicaidBreakdown.days0to15,
                days16to30: medicaidBreakdown.days16to30,
                days31to45: medicaidBreakdown.days31to45,
                withoutTCM: medicaidBreakdown.withoutTCM
            },
            weeklyRiskData: weeklyData, // Add raw weekly risk data for Weekly Risk page
            lastUpdated: new Date().toISOString()
        };
        
        // Cache the results
        dashboardCache = dashboardData;
        dashboardCacheTime = now;
        
        console.log(' Dashboard data cached successfully');
        console.log(' Dashboard data summary:', {
            todayTotal: dashboardData.todayStats.totalAppointments,
            todayKept: dashboardData.todayStats.keptAppointments,
            highRisk: dashboardData.riskBreakdown.highRisk,
            mediumRisk: dashboardData.riskBreakdown.mediumRisk,
            lowRisk: dashboardData.riskBreakdown.lowRisk,
            weekTotal: dashboardData.weekStats.weekToDateTotal,
            medicaidExpiring: dashboardData.medicaidExpiring
        });
        
        res.json(dashboardData);
        
    } catch (error) {
        console.error(' Dashboard data fetch error:', error);
        errorResponses.serverError(res, 'Failed to fetch dashboard data', error.message);
    }
});

// Expiring Medicaid - Clients with Medicaid expiring within 45 days (SQL Server)
app.get('/api/expiring-medicaid', requireAuth, async (req, res) => {
    console.log('Fetching expiring Medicaid data from SQL Server...');
    
    const expiringMedicaidQuery = `
        WITH Latest_HH AS (
            SELECT 
                client_id, 
                med_end_date, 
                enrolled_CMA_name, 
                end_date, 
                ROW_NUMBER() OVER (PARTITION BY client_id ORDER BY chg_datetime DESC) AS rn
            FROM Health_Homes
        )
        SELECT 
            sa.staff_name AS StaffName,
            sa.organization AS Location,
            CONVERT(VARCHAR, sa.service_date, 101) AS ServiceDate,
            LTRIM(STUFF(RIGHT(CONVERT(VARCHAR(19), sa.scheduled_begin_datetime, 0), 7), 6, 0, ' ')) AS BeginTime,
            LTRIM(STUFF(RIGHT(CONVERT(VARCHAR(19), sa.scheduled_end_datetime, 0), 7), 6, 0, ' ')) AS EndTime,
            sa.activity_code AS ActivityCode,
            sa.CLIENT_ID AS ClientID,
            sa.CLIENT_NAME AS ClientName,
            sa.PROGRAM_CODE AS ProgramCode,
            CONVERT(VARCHAR, hh.med_end_date, 101) AS MedicaidEndDate,
            hh.enrolled_CMA_name AS HealthHomeEnrolled,
            CONVERT(VARCHAR, hh.end_date, 101) AS HHEndDate,
            (
                SELECT CONVERT(VARCHAR, MIN(service_date), 101) 
                FROM mv_scheduled_activities
                WHERE client_id = sa.client_id
                AND service_date >= GETDATE()
                AND activity_code IN ('CCB-TCM','CCB-TCMTH')
                AND status = 'None'
                AND last_operation <> 'del'
            ) AS NextTCM
        FROM mv_SCHEDULED_ACTIVITIES sa
        INNER JOIN Latest_HH hh
            ON hh.client_id = sa.client_id
            AND hh.rn = 1
        WHERE sa.TYPE = 'Client'
        AND sa.STATUS = 'None'
        AND sa.service_date >= DATEADD(DD, 1, GETDATE()) 
        AND sa.service_date <= DATEADD(DD, 14, GETDATE())
        AND (
            hh.med_end_date <= DATEADD(DAY, 45, GETDATE())
            OR hh.med_end_date < GETDATE()
        )
        ORDER BY sa.staff_name, sa.SCHEDULED_BEGIN_DATETIME
    `;
    
    try {
        const pool = await sql.connect({
            server: 'IDCC-FB-SQL',
            database: 'Carelogic',
            user: 'sa',
            password: 'Nycems1234$',
            options: {
                encrypt: false,
                trustServerCertificate: true
            }
        });
        
        console.log('Connected to SQL Server (mssql)');
        
        const result = await pool.request().query(expiringMedicaidQuery);
        console.log(`Expiring Medicaid query returned ${result.recordset.length} rows`);
        
        await pool.close();
        res.json({ data: result.recordset || [] });
    } catch (err) {
        console.error('Expiring Medicaid query error:', err);
        res.status(500).json({ error: 'Failed to fetch expiring Medicaid data', details: err.message });
    }
});

// API endpoint to get client criteria details (duplicate - already defined above, keeping this one)
app.get('/api/client-criteria/:clientId', requireAuth, requireSnowflakeReady, (req, res) => {
    const clientId = req.params.clientId;
    console.log(`Fetching criteria for client: ${clientId}`);
    
    const criteriaQuery = `
        WITH latest_intake AS (
            SELECT 
                cd.client_id,
                cd.first_signed_date,
                cd.signed_by_staff,
                cd.signed_by_staff_with_date,
                ROW_NUMBER() OVER (
                    PARTITION BY cd.client_id 
                    ORDER BY cd.first_signed_date DESC
                ) AS rn
            FROM CARELOGIC_PROD.SECURE.mv_client_document cd
            WHERE cd.document_name IN ('IDCC Intake', 'CCBHC Intake', 'IDCC Brief Intake')
              AND cd.first_signed = 'Yes'
              AND cd.deleted <> 'Yes'
              AND TO_DATE(cd.first_signed_date) >= DATEADD(day, -30, CURRENT_DATE())
        )
        SELECT 
            p.person_id,
            p.first_name,
            p.last_name,
            li.first_signed_date AS latest_intake_signed_date,
            li.signed_by_staff AS latest_intake_signed_by,
            
            -- Check intake document requirement
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.mv_client_document mv_doc 
                WHERE mv_doc.client_id = p.person_id 
                AND UPPER(mv_doc.document_name) LIKE '%INTAKE%'
                AND mv_doc.first_signed = 'Yes'
                AND mv_doc.deleted <> 'Yes'
                AND TO_DATE(mv_doc.first_signed_date) >= DATEADD(day, -30, CURRENT_DATE())
            ) THEN true ELSE false END as has_intake_document,
            
            -- Check intake activity requirement
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad2
                JOIN CARELOGIC_PROD.SECURE.activity_log al2 ON ad2.ACTIVITY_LOG_ID = al2.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.activity act2 ON al2.activity_id = act2.activity_id
                WHERE ad2.client_id = p.person_id
                AND UPPER(act2.description) LIKE '%CCBHC%'
                AND UPPER(act2.description) LIKE '%INTAKE%'
                AND ad2.status = 'Kept'
                AND TO_DATE(ad2.actual_begin_datetime) >= DATEADD(day, -30, CURRENT_DATE())
            ) THEN true ELSE false END as has_intake_activity,
            
            -- Check pathway note exclusion
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa_filter
                WHERE mv_sa_filter.client_id = p.person_id
                AND mv_sa_filter.document = 'Clinical Pathway Coordination Note'
                AND TO_DATE(mv_sa_filter.actual_begin_datetime) >= DATEADD(day, -30, CURRENT_DATE())
                AND TO_DATE(mv_sa_filter.actual_begin_datetime) < CURRENT_DATE()
            ) THEN true ELSE false END as has_pathway_note,
            
            -- Check if client has kept sessions today
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad
                WHERE ad.client_id = p.person_id
                AND ad.status = 'Kept'
                AND TO_DATE(ad.actual_begin_datetime) = CURRENT_DATE()
            ) THEN true ELSE false END as session_kept_today,
            
            -- Check if client has kept sessions yesterday
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad
                WHERE ad.client_id = p.person_id
                AND ad.status = 'Kept'
                AND TO_DATE(ad.actual_begin_datetime) = DATEADD(day, -1, CURRENT_DATE())
            ) THEN true ELSE false END as session_kept_yesterday,
            
            -- Get pathway status
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                WHERE ad.client_id = p.person_id
                AND al.activity_id = 1688
                AND ad.status = 'Kept'
                AND TO_DATE(ad.actual_begin_datetime) = CURRENT_DATE()
            ) THEN 'Created' ELSE 'Not Created' END as pathway_status,
            
            -- Get fully signed status
            CASE WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad
                JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.ACTIVITY_LOG_ID = al.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.document doc ON doc.activity_detail_id = ad.activity_detail_id
                WHERE ad.client_id = p.person_id
                AND al.activity_id = 1688
                AND ad.status = 'Kept'
                AND TO_DATE(ad.actual_begin_datetime) = CURRENT_DATE()
                AND doc.FULLY_SIGNED_YN = 'Yes'
            ) THEN true ELSE false END as fully_signed
            
        FROM CARELOGIC_PROD.SECURE.person p
        LEFT JOIN latest_intake li
          ON li.client_id = p.person_id AND li.rn = 1
        WHERE p.person_id = ${clientId}
    `;
    
    executeSnowflakeQuery(criteriaQuery, {
        onSuccess: (rows, res) => {
            console.log(`Query returned ${rows.length} rows`);
            if (rows.length > 0) {
                const criteria = rows[0];
                console.log('Criteria data:', criteria);

                const response = {
                    hasIntakeDocument: criteria.HAS_INTAKE_DOCUMENT,
                    hasIntakeActivity: criteria.HAS_INTAKE_ACTIVITY,
                    hasPathwayNote: criteria.HAS_PATHWAY_NOTE,
                    sessionKept: criteria.SESSION_KEPT_TODAY || criteria.SESSION_KEPT_YESTERDAY,
                    dateMatch: criteria.SESSION_KEPT_TODAY,
                        pathwayStatus: criteria.PATHWAY_STATUS,
                        fullySigned: criteria.FULLY_SIGNED,
                        intakeSignedDate: criteria.LATEST_INTAKE_SIGNED_DATE || null,
                        intakeSignedBy: criteria.LATEST_INTAKE_SIGNED_BY || null,
                        details: [
                            { label: 'Intake Document', value: criteria.HAS_INTAKE_DOCUMENT ? 'Has signed intake document (CCBHC/IDCC)' : 'No signed intake document' },
                            { label: 'Intake Activity', value: criteria.HAS_INTAKE_ACTIVITY ? 'Has CCBHC INTAKE activity' : 'No CCBHC INTAKE activity' },
                            { label: 'Pathway Note', value: criteria.HAS_PATHWAY_NOTE ? 'Has pathway note - EXCLUDED' : 'No pathway note - INCLUDED' },
                            { label: 'Session Kept Today', value: criteria.SESSION_KEPT_TODAY ? 'Yes' : 'No' },
                            { label: 'Session Kept Yesterday', value: criteria.SESSION_KEPT_YESTERDAY ? 'Yes' : 'No' },
                            { label: 'Pathway Status', value: criteria.PATHWAY_STATUS || 'Not Created' },
                            { label: 'Fully Signed', value: criteria.FULLY_SIGNED ? 'Yes' : 'No' }
                        ]
                    };

                    // Fetch recent intake docs (last 30 days) for display
                    const recentIntakesQuery = `
                        SELECT 
                            cd.document_name,
                            cd.first_signed_date,
                            cd.signed_by_staff,
                            cd.signed_by_staff_with_date
                        FROM CARELOGIC_PROD.SECURE.mv_client_document cd
                        WHERE cd.client_id = ${clientId}
                          AND cd.document_name IN ('IDCC Intake', 'CCBHC Intake', 'IDCC Brief Intake')
                          AND cd.first_signed = 'Yes'
                          AND cd.deleted <> 'Yes'
                          AND TO_DATE(cd.first_signed_date) >= DATEADD(day, -30, CURRENT_DATE())
                        ORDER BY cd.first_signed_date DESC
                    `;

                    connection.execute({
                        sqlText: recentIntakesQuery,
                        complete: function(err2, stmt2, rows2) {
                            if (err2) {
                                console.error('Recent intake docs query error:', err2);
                                // Still return base response
                                return res.json(response);
                            }
                            response.recentIntakes = rows2 || [];
                            return res.json(response);
                        }
                    });
                } else {
                    console.log('No rows returned for client:', clientId);
                    res.status(404).json({ error: 'Client not found' });
                }
        }
    }, res, 'Failed to fetch client criteria');
});

// Get all documents for a client from all NYIBDCC_CF_IDCC_ tables
app.get('/api/client-all-documents/:clientId', requireSnowflakeReady, (req, res) => {
    const clientId = req.params.clientId;
    console.log(`[API] /api/client-all-documents/${clientId} endpoint called`);
    console.log(`Fetching all documents for client: ${clientId}`);
    
    // Step 1: Get all document_ids for this client from document table
    // The document table has a direct client_id column
    const getDocumentIdsQuery = `
        SELECT DISTINCT document_id
        FROM CARELOGIC_PROD.SECURE.document
        WHERE client_id = ${clientId}
          AND document_id IS NOT NULL
    `;
    
    // Step 2: Find all tables with the NYIBDCC_CF_IDCC_ prefix that have document_id
    const findTablesQuery = `
        SELECT DISTINCT table_name
        FROM CARELOGIC_PROD.INFORMATION_SCHEMA.TABLES
        WHERE table_schema = 'SECURE'
          AND table_name LIKE 'NYIBDCC_CF_IDCC_%'
        ORDER BY table_name
    `;
    
    // Step 3: Check which of those tables have a document_id column
    const findTablesWithDocumentIdQuery = `
        SELECT DISTINCT t.table_name
        FROM CARELOGIC_PROD.INFORMATION_SCHEMA.TABLES t
        INNER JOIN CARELOGIC_PROD.INFORMATION_SCHEMA.COLUMNS c
            ON t.table_schema = c.table_schema
            AND t.table_name = c.table_name
        WHERE t.table_schema = 'SECURE'
          AND t.table_name LIKE 'NYIBDCC_CF_IDCC_%'
          AND UPPER(c.column_name) = 'DOCUMENT_ID'
        ORDER BY t.table_name
    `;
    
    // Execute queries in sequence
    connection.execute({
        sqlText: getDocumentIdsQuery,
        complete: function(err, stmt, documentIds) {
            if (err) {
                console.error('Error getting document IDs:', err.message);
                return res.status(500).json({ error: 'Failed to get document IDs', details: err.message });
            }
            
            const docIds = (documentIds || []).map(row => row.DOCUMENT_ID);
            console.log(`Found ${docIds.length} document IDs for client ${clientId}`);
            
            if (docIds.length === 0) {
                return res.json({
                    clientId: parseInt(clientId),
                    documentIds: [],
                    tablesFound: [],
                    documentsByTable: {}
                });
            }
            
            // Now find all tables with document_id
            connection.execute({
                sqlText: findTablesWithDocumentIdQuery,
                complete: function(err2, stmt2, tables) {
                    if (err2) {
                        console.error('Error finding tables:', err2.message);
                        return res.status(500).json({ error: 'Failed to find tables', details: err2.message });
                    }
                    
                    const tableNames = (tables || []).map(row => row.TABLE_NAME);
                    console.log(`Found ${tableNames.length} tables with document_id: ${tableNames.join(', ')}`);
                    
                    if (tableNames.length === 0) {
                        return res.json({
                            clientId: parseInt(clientId),
                            documentIds: docIds,
                            tablesFound: [],
                            documentsByTable: {},
                            message: 'No tables with NYIBDCC_CF_IDCC_ prefix found'
                        });
                    }
                    
                    // Build UNION ALL query to get data from all tables
                    // We'll query each table separately to avoid issues with different schemas
                    const tableQueries = tableNames.map(tableName => {
                        return new Promise((resolve, reject) => {
                            const tableQuery = `
                                SELECT 
                                    '${tableName}' AS source_table,
                                    *
                                FROM CARELOGIC_PROD.SECURE."${tableName}"
                                WHERE document_id IN (${docIds.map(id => `'${id}'`).join(',')})
                            `;
                            
                            connection.execute({
                                sqlText: tableQuery,
                                complete: function(err3, stmt3, rows) {
                                    if (err3) {
                                        console.error(`Error querying table ${tableName}:`, err3.message);
                                        // Don't reject - just return empty array for this table
                                        resolve({ tableName, rows: [], error: err3.message });
                                    } else {
                                        resolve({ tableName, rows: rows || [], error: null });
                                    }
                                }
                            });
                        });
                    });
                    
                    Promise.all(tableQueries).then(results => {
                        const documentsByTable = {};
                        let totalDocuments = 0;
                        
                        // Only include tables that have data (rows.length > 0)
                        results.forEach(({ tableName, rows, error }) => {
                            if (rows.length > 0) {
                                documentsByTable[tableName] = {
                                    count: rows.length,
                                    documents: rows
                                };
                                totalDocuments += rows.length;
                            } else if (error) {
                                // Log errors but don't include in response
                                console.error(`Table ${tableName} had error: ${error}`);
                            }
                        });
                        
                        const tablesWithData = Object.keys(documentsByTable);
                        console.log(`Retrieved documents from ${tablesWithData.length} tables (out of ${results.length} queried), total: ${totalDocuments} documents`);
                        
                        res.json({
                            clientId: parseInt(clientId),
                            documentIds: docIds,
                            totalDocumentIds: docIds.length,
                            tablesQueried: tableNames.length,
                            tablesWithData: tablesWithData,
                            totalDocuments: totalDocuments,
                            documentsByTable: documentsByTable
                        });
                    }).catch(err => {
                        console.error('Error executing table queries:', err.message);
                        res.status(500).json({ error: 'Failed to query document tables', details: err.message });
                    });
                }
            });
        }
    });
});

// Volume by Site API endpoint - MTD and YTD
// Cache for volume-by-site data (5 minutes)
let volumeBySiteCache = null;
let volumeBySiteCacheTime = null;
const VOLUME_BY_SITE_CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds

app.get('/api/volume-by-site', requireAuth, (req, res) => {
    console.log(' Fetching volume by site (MTD/YTD)...');
    
    // Check cache first
    const cacheCheckTime = Date.now();
    if (volumeBySiteCache && volumeBySiteCacheTime && (cacheCheckTime - volumeBySiteCacheTime) < VOLUME_BY_SITE_CACHE_TTL) {
        console.log(' Returning cached volume-by-site data');
        return res.json(volumeBySiteCache);
    }
    
    if (!snowflakeReady) {
        console.error(' Snowflake connection not ready');
        return res.status(503).json({ error: 'Database connection not ready. Please try again in a moment.' });
    }
    
    // Calculate MTD and YTD date ranges
    const now = new Date();
    const mtdStart = new Date(now.getFullYear(), now.getMonth(), 1); // First day of current month
    const ytdStart = new Date(now.getFullYear(), 0, 1); // January 1st of current year
    
    // Format dates for Snowflake (YYYY-MM-DD)
    const mtdStartStr = mtdStart.toISOString().split('T')[0];
    const ytdStartStr = ytdStart.toISOString().split('T')[0];
    const todayStr = now.toISOString().split('T')[0];
    
    console.log(`   MTD Start: ${mtdStartStr}`);
    console.log(`   YTD Start: ${ytdStartStr}`);
    console.log(`   Today: ${todayStr}`);
    
    // Define allowed site names (case-insensitive matching)
    const allowedSites = [
        'flatbush',
        'williamsburg',
        'canarsise',
        'canarsie',
        'coney',
        'crown height',
        'crown heights',
        'lsa coney',
        'lsa flatbush',
        'lsa canarsie',
        'lsa crown heights',
        'lsa williamsburg',
        'lsa midwood'
    ];
    
    // Build WHERE clause for site filtering
    const siteFilter = allowedSites.map(site => 
        `UPPER(org.NAME) LIKE '%${site.toUpperCase()}%'`
    ).join(' OR ');
    
    console.log(`   Filtering by sites: ${allowedSites.join(', ')}`);
    console.log(`   Site filter SQL: (${siteFilter})`);
    
    const volumeQuery = `
        WITH site_volume AS (
            SELECT 
                org.ORGANIZATION_ID,
                org.NAME AS site_name,
                -- MTD: Count appointments from start of current month to today
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${mtdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                    THEN 1 
                END) AS mtd_appointments,
                -- YTD: Count appointments from start of current year to today
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${ytdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                    THEN 1 
                END) AS ytd_appointments,
                -- MTD Kept appointments
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${mtdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                     AND ad.status = 'Kept'
                    THEN 1 
                END) AS mtd_kept,
                -- YTD Kept appointments
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${ytdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                     AND ad.status = 'Kept'
                    THEN 1 
                END) AS ytd_kept,
                -- MTD Missed (DNS, CBC, CBT)
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${mtdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                     AND ad.status IN ('DNS', 'CBC', 'CBT')
                    THEN 1 
                END) AS mtd_missed,
                -- YTD Missed
                COUNT(CASE 
                    WHEN TO_DATE(ad.actual_begin_datetime) >= '${ytdStartStr}' 
                     AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
                     AND ad.status IN ('DNS', 'CBC', 'CBT')
                    THEN 1 
                END) AS ytd_missed
            FROM CARELOGIC_PROD.SECURE.activity_log al
            JOIN CARELOGIC_PROD.SECURE.activity_detail ad ON al.activity_log_id = ad.activity_log_id
            JOIN CARELOGIC_PROD.SECURE.organization org ON al.organization_id = org.organization_id
            JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
            WHERE TO_DATE(ad.actual_begin_datetime) >= '${ytdStartStr}'  -- At least YTD range
              AND TO_DATE(ad.actual_begin_datetime) <= '${todayStr}'
              AND UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
              AND ad.status IS NOT NULL
              AND ad.status IN ('Kept', 'DNS', 'CBC', 'CBT')  -- Only include valid statuses, exclude error statuses
              AND (${siteFilter})  -- Filter by allowed sites only
              AND UPPER(org.NAME) NOT LIKE '%WILLIAMSBURG HIGH SCHOOL%'  -- Exclude Williamsburg High School
            GROUP BY org.ORGANIZATION_ID, org.NAME
        )
        SELECT 
            site_name,
            mtd_appointments,
            mtd_kept,
            mtd_missed,
            CASE 
                WHEN mtd_appointments > 0 
                THEN ROUND((mtd_kept::FLOAT / mtd_appointments::FLOAT) * 100, 1)
                ELSE 0 
            END AS mtd_attendance_rate,
            ytd_appointments,
            ytd_kept,
            ytd_missed,
            CASE 
                WHEN ytd_appointments > 0 
                THEN ROUND((ytd_kept::FLOAT / ytd_appointments::FLOAT) * 100, 1)
                ELSE 0 
            END AS ytd_attendance_rate
        FROM site_volume
        WHERE mtd_appointments > 0 OR ytd_appointments > 0  -- Only show sites with activity
        ORDER BY ytd_appointments DESC, site_name ASC
    `;
    
    console.log('Executing volume by site query...');
    executeSnowflakeQuery(volumeQuery, {
        onSuccess: (rows, res) => {
            console.log(` Query returned ${rows.length} rows`);
            
            // Calculate totals
            const totals = {
                mtd_appointments: 0,
                mtd_kept: 0,
                mtd_missed: 0,
                ytd_appointments: 0,
                ytd_kept: 0,
                ytd_missed: 0
            };
            
            rows.forEach(row => {
                totals.mtd_appointments += row.MTD_APPOINTMENTS || 0;
                totals.mtd_kept += row.MTD_KEPT || 0;
                totals.mtd_missed += row.MTD_MISSED || 0;
                totals.ytd_appointments += row.YTD_APPOINTMENTS || 0;
                totals.ytd_kept += row.YTD_KEPT || 0;
                totals.ytd_missed += row.YTD_MISSED || 0;
            });
            
            // Calculate attendance rates for totals
            totals.mtd_attendance_rate = totals.mtd_appointments > 0 
                ? Math.round((totals.mtd_kept / totals.mtd_appointments) * 100 * 10) / 10 
                : 0;
            totals.ytd_attendance_rate = totals.ytd_appointments > 0 
                ? Math.round((totals.ytd_kept / totals.ytd_appointments) * 100 * 10) / 10 
                : 0;
            
            // Convert to camelCase for frontend
            const formattedRows = rows.map(row => ({
                siteName: row.SITE_NAME,
                mtdAppointments: row.MTD_APPOINTMENTS || 0,
                mtdKept: row.MTD_KEPT || 0,
                mtdMissed: row.MTD_MISSED || 0,
                mtdAttendanceRate: row.MTD_ATTENDANCE_RATE || 0,
                ytdAppointments: row.YTD_APPOINTMENTS || 0,
                ytdKept: row.YTD_KEPT || 0,
                ytdMissed: row.YTD_MISSED || 0,
                ytdAttendanceRate: row.YTD_ATTENDANCE_RATE || 0
            }));
            
            const responseData = { 
                data: formattedRows,
                totals: totals,
                period: {
                    mtdStart: mtdStartStr,
                    ytdStart: ytdStartStr,
                    today: todayStr
                }
            };
            
            // Cache the response
            volumeBySiteCache = responseData;
            volumeBySiteCacheTime = Date.now();
            console.log(' Cached volume-by-site data (will expire in 5 minutes)');
            
            res.json(responseData);
        }
    }, res, 'Failed to fetch volume by site data');
});

// Medical Examination Report - Clients without recent medical exams (within next 14 days)
app.get('/api/medical-examination-report', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log(' Fetching medical examination report...');
    
    const locations = LOCATIONS_WITH_LSA;
    
    // Base SQL query
    const baseSql = `
WITH annual_med AS (
    SELECT client_id, MAX(created_date_time) AS last_med
    FROM mv_client_document
    WHERE (document_name = 'IDCC Medical Examination Report at Intake'
    OR document_name = 'IDCC Annual Medical Examination Report')
    AND deleted <> 'Yes'
    AND LAST_OPERATION <> 'del'
    GROUP BY client_id
)

SELECT 
    sa.staff_id, 
    NVL(sa.staff_name, 'None') AS "Staff Name", 
    sa.ORGANIZATION, 
    sa.client_id AS "Client ID", 
    sa.client_name AS "Client Name", 
    TO_CHAR(sa.service_date, 'MM/dd/yyyy') AS "Service Date", 
    sa.program_code, 
    sa.activity_code AS "Activity Code", 
    sa.activity_name,
    TO_CHAR(sa.scheduled_begin_datetime, 'HH12:MI AM') AS "Begin Time", 
    TO_CHAR(annual_med.last_med, 'MM/dd/yyyy') AS "Last Medical",
    (SELECT TO_VARCHAR(MIN(TO_DATE(service_date)), 'MM/dd/yyyy') 
     FROM mv_scheduled_activities
     WHERE client_id = sa.client_id
     AND TO_DATE(service_date) >= TO_DATE(CURRENT_DATE())
     AND activity_code IN ('CCB-TCM','CCB-TCMTH')
     AND status = 'None'
     AND last_operation <> 'del') AS "Next TCM"
FROM mv_scheduled_activities sa
LEFT JOIN annual_med ON annual_med.client_id = sa.client_id
WHERE TO_DATE(service_date) >= CURRENT_DATE() 
AND TO_DATE(service_date) <= DATEADD(DAY, 14, CURRENT_TIMESTAMP())
AND sa.status = 'None'
AND sa.TYPE IN ('Client','Group')
`;
    
    // Collect all results
    const allResults = [];
    let completedQueries = 0;
    const totalQueries = locations.length - 1; // Exclude empty string at index 0
    
    // Process each location (skip index 0 which is empty string)
    for (let loc = 1; loc < locations.length; loc++) {
        const doingLocation = locations[loc];
        console.log(`   Processing location: ${doingLocation}`);
        
        let sql = baseSql;
        
        // Add location filter
        if (doingLocation === "Schools") {
            sql += ` AND sa.organization IN (SELECT name FROM organization WHERE parent_org_id = 1009)`;
        } else {
            sql += ` AND sa.organization = '${doingLocation}'`;
        }
        
        sql += `
AND sa.last_operation <> 'del'
AND (annual_med.last_med IS NULL 
OR annual_med.last_med < DATEADD(DAY, -365, CURRENT_DATE()))
ORDER BY sa.service_date, sa.scheduled_begin_datetime, sa.client_name
`;
        
        // Execute query for this location
        connection.execute({
            sqlText: sql,
            complete: function(err, stmt, rows) {
                completedQueries++;
                
                if (err) {
                    console.error(` Error querying location ${doingLocation}:`, err.message);
                    // Continue with other locations even if one fails
                    if (completedQueries === totalQueries) {
                        // All queries completed, send response
                        console.log(` Medical exam report complete. Total rows: ${allResults.length}`);
                        res.json({
                            data: allResults,
                            totalRows: allResults.length,
                            locations: locations.slice(1), // Exclude empty string
                            generated: new Date().toISOString()
                        });
                    }
                    return;
                }
                
                console.log(`    ${doingLocation}: ${rows ? rows.length : 0} rows`);
                
                // Add location column and add to results
                (rows || []).forEach(row => {
                    allResults.push({
                        location: doingLocation,
                        staffId: row.STAFF_ID,
                        staffName: row['Staff Name'] || 'None',
                        organization: row.ORGANIZATION,
                        clientId: row['Client ID'],
                        clientName: row['Client Name'],
                        serviceDate: row['Service Date'],
                        programCode: row.PROGRAM_CODE,
                        activityCode: row['Activity Code'],
                        activityName: row.ACTIVITY_NAME,
                        beginTime: row['Begin Time'],
                        lastMedical: row['Last Medical'] || 'Never',
                        nextTCM: row['Next TCM'] || 'None'
                    });
                });
                
                // Check if all queries are complete
                if (completedQueries === totalQueries) {
                    console.log(` Medical exam report complete. Total rows: ${allResults.length}`);
                    res.json({
                        data: allResults,
                        totalRows: allResults.length,
                        locations: locations.slice(1), // Exclude empty string
                        generated: new Date().toISOString()
                    });
                }
            }
        });
    }
});

// PHQ-9 Report - Client PHQ-9 assessment for a specific date
app.get('/api/phq9-report', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log(' Fetching PHQ-9 report...');
    
    // Get query parameters - use specific date instead of start_date
    const selectedDate = req.query.date || req.query.start_date || new Date().toISOString().split('T')[0];
    console.log(` PHQ-9 report requested for date: ${selectedDate}`);
    console.log(`Using measure filter: measure IN ('PHQ-9', 'PHQ-9A')`);
    
    // First, let's check what dates actually have PHQ-9 data (for debugging)
    const dateCheckSql = `
        SELECT DISTINCT TO_DATE(service_date) as service_date, COUNT(*) as count
        FROM mv_impact_data
        WHERE measure IN ('PHQ-9', 'PHQ-9A')
            AND last_operation <> 'del'
            AND TO_DATE(service_date) >= DATEADD(DAY, -30, CURRENT_DATE())
        GROUP BY TO_DATE(service_date)
        ORDER BY service_date DESC
        LIMIT 10
    `;
    
    connection.execute({
        sqlText: dateCheckSql,
        complete: function(err, stmt, rows) {
            if (!err && rows && rows.length > 0) {
                console.log(` [PHQ-9] Available dates with data (last 10):`, rows.map(r => r.SERVICE_DATE));
            } else if (!err) {
                console.log(` [PHQ-9] No PHQ-9 data found in last 30 days`);
            }
        }
    });
    
    const locations = req.query.locations ? req.query.locations.split(',') : STANDARD_LOCATIONS;
    
    // Base SQL query - filter by exact date
    // Using measure IN ('PHQ-9', 'PHQ-9A') for PHQ-9 (as per original query)
    // Using INNER JOIN on mv_impact_data to only show clients with PHQ-9 data for the selected date
    const baseSql = `
SELECT DISTINCT
    cp.staff_id as "Staff ID",
    s.full_name_alternate as "Staff Name", 
    s.current_credential as "Credentials", 
    c.client_id as "Client ID",  
    c.full_name_alternate as "Client Name", 
    c.age AS "Age", 
    TO_CHAR(mv_impact.service_date, 'MM/dd/yyyy') AS "PHQ-9 Date",
    TO_VARCHAR(mv_impact.score) AS "PHQ-9 Score"
FROM mv_CLIENT c
    INNER JOIN client_program cp ON cp.client_id = c.client_id AND cp.LAST_OPERATION <> 'del'
    LEFT JOIN mv_staff s ON s.staff_id = cp.staff_id AND s.LAST_OPERATION <> 'del'
    INNER JOIN mv_client_document client_doc ON c.client_id = client_doc.client_id 
        AND client_doc.LAST_OPERATION <> 'del'
        AND client_doc.deleted <> 'Yes'
    INNER JOIN mv_impact_data mv_impact ON mv_impact.document_id = client_doc.document_id
        AND mv_impact.measure IN ('PHQ-9', 'PHQ-9A')
        AND TO_DATE(mv_impact.service_date) = TO_DATE('${selectedDate}')
        AND mv_impact.last_operation <> 'del'
WHERE c.LAST_OPERATION <> 'del'
    AND cp.begin_date IS NOT NULL
    AND cp.end_date IS NULL
    AND cp.priority = 1
    AND c.client_id NOT IN (2324,2325,7262,7264,41734,42342,54302,59113,71109,73459,75821,76370,76392,76401,76402,77659,90059,90473,90498,92655,99819,101751,103382,108967,108989,109657)
`;
    
    // Collect all results
    const allResults = [];
    let completedQueries = 0;
    const totalQueries = locations.length;
    
    // Process each location
    locations.forEach((doingLocation, index) => {
        let sql = baseSql;
        
        // Add location filter to WHERE clause
        if (["Flatbush", "Crown Heights", "Williamsburg", "Canarsie", "Coney Island", "Home Based", "ACT"].includes(doingLocation)) {
            sql += ` AND cp.organization_id = (SELECT organization_id FROM organization WHERE name = '${doingLocation}')`;
        } else if (doingLocation === "Schools") {
            sql += ` AND cp.organization_id IN (SELECT organization_id FROM organization WHERE PARENT_ORG_ID = 1009)`;
        } else if (doingLocation === "Iop") {
            sql += ` AND cp.program_id = 1027`;
        } else {
            sql += ` AND cp.organization_id = (SELECT organization_id FROM organization WHERE name = '${doingLocation}')`;
        }
        
        sql += `
ORDER BY s.full_name_alternate, c.full_name_alternate
`;
        
        console.log(`   [PHQ-9] Processing location: ${doingLocation} for date: ${selectedDate}`);
        
        // Execute query for this location
        connection.execute({
            sqlText: sql,
            complete: function(err, stmt, rows) {
                completedQueries++;
                
                if (err) {
                    console.error(` [PHQ-9] Error querying location ${doingLocation}:`, err.message);
                    console.error(` [PHQ-9] Full error:`, err);
                    // Continue with other locations even if one fails
                    if (completedQueries === totalQueries) {
                        // All queries completed, send response
                        console.log(` [PHQ-9] Report complete. Total rows: ${allResults.length}`);
                        res.json({
                            data: allResults,
                            totalRows: allResults.length,
                            locations: locations,
                            date: selectedDate,
                            generated: new Date().toISOString()
                        });
                    }
                    return;
                }
                
                const rowCount = rows ? rows.length : 0;
                console.log(`    [PHQ-9] ${doingLocation}: ${rowCount} rows`);
                
                if (rowCount === 0) {
                    console.log(`    [PHQ-9] No data found for ${doingLocation} on ${selectedDate}`);
                } else {
                    console.log(`    [PHQ-9] Raw sample row from ${doingLocation}:`, rows[0]);
                    console.log(`    [PHQ-9] Row keys:`, Object.keys(rows[0]));
                }
                
                // Add location column and add to results
                if (rows && rows.length > 0) {
                    console.log(`    [PHQ-9] Processing ${rows.length} rows from ${doingLocation}`);
                    (rows || []).forEach((row, idx) => {
                        // Debug: log the raw row structure
                        if (idx === 0) {
                            console.log(`   [PHQ-9] Raw row keys:`, Object.keys(row));
                            console.log(`   [PHQ-9] Raw row values:`, row);
                        }
                        
                        const mappedRow = {
                            location: doingLocation,
                            staffId: row['Staff ID'] || row['STAFF ID'] || row.STAFF_ID || null,
                            staffName: row['Staff Name'] || row['STAFF NAME'] || row.STAFF_NAME || '',
                            credentials: row['Credentials'] || row.CREDENTIALS || '',
                            clientId: row['Client ID'] || row['CLIENT ID'] || row.CLIENT_ID || null,
                            clientName: row['Client Name'] || row['CLIENT NAME'] || row.CLIENT_NAME || '',
                            age: row['Age'] || row.AGE || null,
                            phq9Date: row['PHQ-9 Date'] || row['PHQ-9 DATE'] || row['PHQ_9_DATE'] || '',
                            phq9Score: row['PHQ-9 Score'] || row['PHQ-9 SCORE'] || row['PHQ_9_SCORE'] || ''
                        };
                        allResults.push(mappedRow);
                        if (idx === 0) {
                            console.log(`    [PHQ-9] Mapped row sample:`, JSON.stringify(mappedRow, null, 2));
                        }
                    });
                    console.log(`    [PHQ-9] Added ${rows.length} rows from ${doingLocation}. Total so far: ${allResults.length}`);
                }
                
                // Check if all queries are complete
                if (completedQueries === totalQueries) {
                    console.log(` [PHQ-9] Report complete. Total rows: ${allResults.length}`);
                    console.log(` [PHQ-9] Sample data (first 3 rows):`, allResults.slice(0, 3));
                    console.log(` [PHQ-9] Sending response with ${allResults.length} rows`);
                    res.json({
                        data: allResults,
                        totalRows: allResults.length,
                        locations: locations,
                        date: selectedDate,
                        generated: new Date().toISOString()
                    });
                }
            }
        });
    });
});

// Get client email by client ID (EHR ID)
// Note: Auth removed for Chrome extension compatibility
app.get('/api/client-email/:clientId', requireSnowflakeReady, (req, res) => {
    const clientId = req.params.clientId;
    
    if (!clientId) {
        return errorResponses.badRequest(res, 'Client ID is required');
    }
    
    console.log(` Looking up email for client ID: ${clientId}`);
    
    // Query to get client email from person_contact table
    // Email is in person_contact.email1
    // First verify person exists, then get email from person_contact
    // Use CTE with QUALIFY to get the first non-null email if multiple contact records exist
    const clientEmailQuery = `
        WITH person_contact_email AS (
            SELECT 
                pc.person_id,
                pc.email1,
                ROW_NUMBER() OVER (PARTITION BY pc.person_id ORDER BY pc.person_contact_id) AS rn
            FROM person_contact pc
            WHERE pc.person_id = ${parseInt(clientId)}
              AND pc.email1 IS NOT NULL 
              AND pc.email1 <> ''
        )
        SELECT 
            p.person_id AS client_id,
            pce.email1 AS email
        FROM person p
        LEFT JOIN person_contact_email pce ON pce.person_id = p.person_id AND pce.rn = 1
        WHERE p.person_id = ${parseInt(clientId)}
    `;
    
    executeSnowflakeQuery(clientEmailQuery, {
        onSuccess: (rows, res) => {
            if (!rows || rows.length === 0) {
                console.log(` No client found with ID: ${clientId}`);
                return res.json({
                    clientId: clientId,
                    email: null,
                    found: false,
                    message: 'Client not found in database'
                });
            }
            
            // Snowflake returns column names in uppercase
            // We aliased as 'email', so it should be EMAIL
            // But also check EMAIL1 in case Snowflake uses original column name
            const row = rows[0];
            console.log(`   Row data keys:`, Object.keys(row));
            console.log(`   Row data:`, JSON.stringify(row, null, 2));
            
            const clientEmail = row.EMAIL || row.EMAIL1 || null;
            const found = clientEmail && typeof clientEmail === 'string' && clientEmail.trim() !== '';
            
            console.log(` Client ${clientId} email lookup: ${found ? 'Found' : 'Not found'} - ${clientEmail || 'N/A'}`);
            
            res.json({
                clientId: clientId,
                email: found ? clientEmail : null,
                found: found || false, // Ensure it's always a boolean
                message: found ? 'Email found' : 'Client found but no email on record'
            });
        }
    }, res, 'Failed to lookup client email');
});

// Get staff email by staff ID
// Note: Auth removed for Chrome extension compatibility
app.get('/api/staff-email/:staffId', requireSnowflakeReady, (req, res) => {
    const staffId = req.params.staffId;
    
    if (!staffId) {
        return errorResponses.badRequest(res, 'Staff ID is required');
    }
    
    console.log(` Looking up email for staff ID: ${staffId}`);
    
    // Query to get staff email from staff_Contact_info table
    // Email is in staff_Contact_info.email_address
    // First verify staff exists, then get email from staff_Contact_info
    // Use QUALIFY to get the first non-null email if multiple contact records exist
    const staffEmailQuery = `
        SELECT 
            s.staff_id,
            sci.email_address AS email
        FROM staff s
        LEFT JOIN staff_Contact_info sci ON sci.staff_id = s.staff_id
            AND sci.email_address IS NOT NULL 
            AND sci.email_address <> ''
        WHERE s.staff_id = ${parseInt(staffId)}
        QUALIFY ROW_NUMBER() OVER (PARTITION BY s.staff_id ORDER BY sci.email_address) = 1
    `;
    
    executeSnowflakeQuery(staffEmailQuery, {
        onSuccess: (rows, res) => {
            if (!rows || rows.length === 0) {
                console.log(` No staff found with ID: ${staffId}`);
                return res.json({
                    staffId: staffId,
                    email: null,
                    found: false,
                    message: 'Staff not found in database'
                });
            }
            
            // Snowflake returns column names in uppercase
            // We aliased as 'email', so it should be EMAIL
            // But also check EMAIL_ADDRESS in case Snowflake uses original column name
            const row = rows[0];
            console.log(`   Row data keys:`, Object.keys(row));
            console.log(`   Row data:`, JSON.stringify(row, null, 2));
            
            const staffEmail = row.EMAIL || row.EMAIL_ADDRESS || null;
            const found = staffEmail && typeof staffEmail === 'string' && staffEmail.trim() !== '';
            
            console.log(` Staff ${staffId} email lookup: ${found ? 'Found' : 'Not found'} - ${staffEmail || 'N/A'}`);
            
            res.json({
                staffId: staffId,
                email: found ? staffEmail : null,
                found: found || false, // Ensure it's always a boolean
                message: found ? 'Email found' : 'Staff found but no email on record'
            });
        }
    }, res, 'Failed to lookup staff email');
});

// GAD-7 Report - Client GAD-7 assessment for a specific date
app.get('/api/gad7-report', requireAuth, requireSnowflakeReady, (req, res) => {
    console.log(' Fetching GAD-7 report...');
    
    // Get query parameters - use specific date instead of start_date
    const selectedDate = req.query.date || req.query.start_date || new Date().toISOString().split('T')[0];
    console.log(` GAD-7 report requested for date: ${selectedDate}`);
    console.log(`Using measure filter: measure = 'GAD-7'`);
    
    // First, let's check what dates actually have GAD-7 data (for debugging)
    const dateCheckSql = `
        SELECT DISTINCT TO_DATE(service_date) as service_date, COUNT(*) as count
        FROM mv_impact_data
        WHERE measure = 'GAD-7'
            AND last_operation <> 'del'
            AND TO_DATE(service_date) >= DATEADD(DAY, -30, CURRENT_DATE())
        GROUP BY TO_DATE(service_date)
        ORDER BY service_date DESC
        LIMIT 10
    `;
    
    connection.execute({
        sqlText: dateCheckSql,
        complete: function(err, stmt, rows) {
            if (!err && rows && rows.length > 0) {
                console.log(` [GAD-7] Available dates with data (last 10):`, rows.map(r => r.SERVICE_DATE));
            } else if (!err) {
                console.log(` [GAD-7] No GAD-7 data found in last 30 days`);
            }
        }
    });
    
    const locations = req.query.locations ? req.query.locations.split(',') : STANDARD_LOCATIONS;
    
    // Base SQL query - filter by exact date
    // Using measure = 'GAD-7' (as per user's query)
    // Using INNER JOIN on mv_impact_data to only show clients with GAD-7 data for the selected date
    const baseSql = `
SELECT DISTINCT
    cp.staff_id as "Staff ID",
    s.full_name_alternate as "Staff Name", 
    s.current_credential as "Credentials", 
    c.client_id as "Client ID",  
    c.full_name_alternate as "Client Name", 
    c.age AS "Age", 
    TO_CHAR(mv_impact.service_date, 'MM/dd/yyyy') AS "GAD-7 Date",
    TO_VARCHAR(mv_impact.score) AS "GAD-7 Score"
FROM mv_CLIENT c
    INNER JOIN client_program cp ON cp.client_id = c.client_id AND cp.LAST_OPERATION <> 'del'
    LEFT JOIN mv_staff s ON s.staff_id = cp.staff_id AND s.LAST_OPERATION <> 'del'
    INNER JOIN mv_client_document client_doc ON c.client_id = client_doc.client_id 
        AND client_doc.LAST_OPERATION <> 'del'
        AND client_doc.deleted <> 'Yes'
    INNER JOIN mv_impact_data mv_impact ON mv_impact.document_id = client_doc.document_id
        AND mv_impact.measure = 'GAD-7'
        AND TO_DATE(mv_impact.service_date) = TO_DATE('${selectedDate}')
        AND mv_impact.last_operation <> 'del'
WHERE c.LAST_OPERATION <> 'del'
    AND cp.begin_date IS NOT NULL
    AND cp.end_date IS NULL
    AND cp.priority = 1
    AND c.client_id NOT IN (2324,2325,7262,7264,41734,42342,54302,59113,71109,73459,75821,76370,76392,76401,76402,77659,90059,90473,90498,92655,99819,101751,103382,108967,108989,109657)
`;
    
    // Collect all results
    const allResults = [];
    let completedQueries = 0;
    const totalQueries = locations.length;
    
    // Process each location
    locations.forEach((doingLocation, index) => {
        let sql = baseSql;
        
        // Add location filter to WHERE clause
        if (["Flatbush", "Crown Heights", "Williamsburg", "Canarsie", "Coney Island", "Home Based", "ACT"].includes(doingLocation)) {
            sql += ` AND cp.organization_id = (SELECT organization_id FROM organization WHERE name = '${doingLocation}')`;
        } else if (doingLocation === "Schools") {
            sql += ` AND cp.organization_id IN (SELECT organization_id FROM organization WHERE PARENT_ORG_ID = 1009)`;
        } else if (doingLocation === "Iop") {
            sql += ` AND cp.program_id = 1027`;
        } else {
            sql += ` AND cp.organization_id = (SELECT organization_id FROM organization WHERE name = '${doingLocation}')`;
        }
        
        sql += `
ORDER BY s.full_name_alternate, c.full_name_alternate
`;
        
        console.log(`   [GAD-7] Processing location: ${doingLocation} for date: ${selectedDate}`);
        
        // Execute query for this location
        connection.execute({
            sqlText: sql,
            complete: function(err, stmt, rows) {
                completedQueries++;
                
                if (err) {
                    console.error(` [GAD-7] Error querying location ${doingLocation}:`, err.message);
                    console.error(` [GAD-7] Full error:`, err);
                    // Continue with other locations even if one fails
                    if (completedQueries === totalQueries) {
                        // All queries completed, send response
                        console.log(` [GAD-7] Report complete. Total rows: ${allResults.length}`);
                        res.json({
                            data: allResults,
                            totalRows: allResults.length,
                            locations: locations,
                            date: selectedDate,
                            generated: new Date().toISOString()
                        });
                    }
                    return;
                }
                
                const rowCount = rows ? rows.length : 0;
                console.log(`    [GAD-7] ${doingLocation}: ${rowCount} rows`);
                
                if (rowCount === 0) {
                    console.log(`    [GAD-7] No data found for ${doingLocation} on ${selectedDate}`);
                } else {
                    console.log(`    [GAD-7] Sample row from ${doingLocation}:`, rows[0]);
                }
                
                // Add location column and add to results
                if (rows && rows.length > 0) {
                    console.log(`    [GAD-7] Processing ${rows.length} rows from ${doingLocation}`);
                    (rows || []).forEach((row, idx) => {
                        const mappedRow = {
                            location: doingLocation,
                            staffId: row['Staff ID'],
                            staffName: row['Staff Name'] || '',
                            credentials: row['Credentials'] || '',
                            clientId: row['Client ID'],
                            clientName: row['Client Name'] || '',
                            age: row['Age'],
                            gad7Date: row['GAD-7 Date'] || '',
                            gad7Score: row['GAD-7 Score'] || '',
                        };
                        allResults.push(mappedRow);
                        if (idx === 0) {
                            console.log(`    [GAD-7] First row sample:`, JSON.stringify(mappedRow));
                        }
                    });
                    console.log(`    [GAD-7] Added ${rows.length} rows from ${doingLocation}. Total so far: ${allResults.length}`);
                }
                
                // If all queries completed, send response
                if (completedQueries === totalQueries) {
                    console.log(` [GAD-7] Report complete. Total rows: ${allResults.length}`);
                    console.log(` [GAD-7] Sample data (first 3 rows):`, allResults.slice(0, 3));
                    console.log(` [GAD-7] Sending response with ${allResults.length} rows`);
                    res.json({
                        data: allResults,
                        totalRows: allResults.length,
                        locations: locations,
                        date: selectedDate,
                        generated: new Date().toISOString()
                    });
                }
            }
        });
    });
});

// Cache for client cross-report data (5 minutes)
let clientCrossReportCache = null;
let clientCrossReportCacheTime = null;
const CLIENT_CROSS_REPORT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds
const CLIENT_CROSS_REPORT_REFRESH_INTERVAL = 4 * 60 * 1000; // Refresh every 4 minutes (before cache expires)
let clientCrossReportRefreshInterval = null;

// Function to fetch and cache client cross-report data
async function fetchClientCrossReportData() {
    console.log('Starting client cross-report data fetch...');
    console.log(`   Snowflake ready: ${snowflakeReady}`);
    console.log(`   Current time: ${new Date().toISOString()}`);
    
    // Helper function to split concatenated locations
    // Handles cases like "LSA CommunityLSA Crown Heights" -> ["LSA Community", "LSA Crown Heights"]
    function splitConcatenatedLocations(locationStr) {
        if (!locationStr || typeof locationStr !== 'string') return [];
        const trimmed = locationStr.trim();
        if (!trimmed) return [];
        
        // Check if "LSA" appears multiple times (indicates concatenation)
        const lsaMatches = trimmed.match(/LSA/gi);
        if (lsaMatches && lsaMatches.length > 1) {
            // Split on "LSA" (case insensitive) - each match becomes the start of a new location
            const parts = trimmed.split(/(?=LSA)/i).map(p => p.trim()).filter(p => p);
            if (parts.length > 1) {
                console.log(`    Split concatenated location: "${trimmed}" -> [${parts.join(', ')}]`);
                return parts;
            }
        }
        
        // Check for other patterns like "Crown HeightsLSA Midwood" or "CommunityLSA"
        // Look for capital letter after lowercase (e.g., "HeightsLSA" or "CommunityLSA")
        const capitalAfterLowercase = /([a-z])([A-Z])/;
        if (capitalAfterLowercase.test(trimmed)) {
            // Split on capital letters that follow lowercase
            const parts = trimmed.split(/(?=[A-Z])/).map(p => p.trim()).filter(p => p);
            // Only split if we get meaningful parts (more than 1 and each part has at least 3 chars)
            if (parts.length > 1 && parts.every(p => p.length >= 3)) {
                console.log(`    Split location by capital letter pattern: "${trimmed}" -> [${parts.join(', ')}]`);
                return parts;
            }
        }
        
        // No concatenation detected, return as single location
        return [trimmed];
    }
    
    const clientMap = new Map(); // clientId -> { clientName, reports: [], locations: [] }
    
    // Helper function to process rows and add to clientMap
    function processRows(rows, reportName, clientMap) {
        if (!rows || rows.length === 0) return 0;
        
        let addedCount = 0;
        rows.forEach((row, index) => {
            // Handle different column name formats
            const clientId = String(row['CLIENT_ID'] || row['Client ID'] || row['client_id'] || row.CLIENT_ID || row.PERSON_ID || row.person_id || '');
            const clientName = row['CLIENT_NAME'] || row['Client Name'] || row['client_name'] || row.CLIENT_NAME || 
                              (row.LAST_NAME && row.FIRST_NAME ? `${row.LAST_NAME || row.last_name}, ${row.FIRST_NAME || row.first_name}` : 
                               (row.last_name && row.first_name ? `${row.last_name}, ${row.first_name}` : 
                                (row.LAST_NAME || row.last_name || row.FIRST_NAME || row.first_name || 'Unknown')));
            const location = row['LOCATION'] || row['location'] || row.LOCATION || row.ORGANIZATION || row.Location || '';
            
            // Debug: Log first few rows that fail to extract clientId
            if (index < 3 && (!clientId || clientId === 'null' || clientId === 'undefined' || clientId.trim() === '')) {
                console.log(`[processRows] Row ${index} - Could not extract clientId. Row keys:`, Object.keys(row));
                console.log(`[processRows] Row ${index} - Full row:`, JSON.stringify(row, null, 2));
            }
            
            if (clientId && clientId !== 'null' && clientId !== 'undefined' && clientId.trim() !== '') {
                if (!clientMap.has(clientId)) {
                    clientMap.set(clientId, { clientName, reports: [], locations: [] });
                }
                if (!clientMap.get(clientId).reports.includes(reportName)) {
                    clientMap.get(clientId).reports.push(reportName);
                    addedCount++;
                }
                if (location && location.trim() !== '') {
                    const locations = splitConcatenatedLocations(location);
                    locations.forEach(loc => {
                        if (loc && loc.trim() && !clientMap.get(clientId).locations.includes(loc)) {
                            clientMap.get(clientId).locations.push(loc);
                        }
                    });
                }
            }
        });
        return addedCount;
    }
    
    try {
        console.log(' Starting parallel queries for client cross-report...');
        const startTime = Date.now();
        
        // Build array of query promises (all start at once)
        const queryPromises = [];
        
        // 1. Medical Examination Report (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    const medicalSql = `
                        SELECT DISTINCT 
                            sa.client_id,
                            sa.client_name,
                            sa.organization AS location
                        FROM mv_scheduled_activities sa
                        LEFT JOIN (
                            SELECT client_id, MAX(created_date_time) AS last_med
                            FROM mv_client_document
                            WHERE (document_name = 'IDCC Medical Examination Report at Intake'
                            OR document_name = 'IDCC Annual Medical Examination Report')
                            AND deleted <> 'Yes'
                            AND LAST_OPERATION <> 'del'
                            GROUP BY client_id
                        ) annual_med ON annual_med.client_id = sa.client_id
                        WHERE TO_DATE(service_date) >= CURRENT_DATE() 
                        AND TO_DATE(service_date) <= DATEADD(DAY, 14, CURRENT_TIMESTAMP())
                        AND sa.status = 'None'
                        AND sa.TYPE IN ('Client','Group')
                        AND sa.last_operation <> 'del'
                        AND (annual_med.last_med IS NULL 
                        OR annual_med.last_med < DATEADD(DAY, -365, CURRENT_DATE()))
                    `;
                    
                    connection.execute({
                        sqlText: medicalSql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error(' Medical Examination Report query error:', err.message);
                                resolve({ reportName: 'Yearly Medical Examination Report', rows: [], error: err.message });
                            } else {
                                const count = processRows(rows, 'Yearly Medical Examination Report', clientMap);
                                console.log(` Medical Examination Report: ${rows ? rows.length : 0} rows, ${count} clients added`);
                                resolve({ reportName: 'Yearly Medical Examination Report', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // 2. Expiring Medicaid (SQL Server)
        queryPromises.push(
            (async () => {
                try {
                    const pool = await sql.connect({
                        server: 'IDCC-FB-SQL',
                        database: 'Carelogic',
                        user: 'sa',
                        password: 'Nycems1234$',
                        options: {
                            encrypt: false,
                            trustServerCertificate: true
                        }
                    });
                    
                    const expiringMedicaidQuery = `
                        WITH Latest_HH AS (
                            SELECT 
                                client_id, 
                                med_end_date, 
                                enrolled_CMA_name, 
                                end_date, 
                                ROW_NUMBER() OVER (PARTITION BY client_id ORDER BY chg_datetime DESC) AS rn
                            FROM Health_Homes
                        )
                        SELECT DISTINCT
                            sa.CLIENT_ID AS ClientID,
                            sa.CLIENT_NAME AS ClientName,
                            '' AS Location
                        FROM mv_SCHEDULED_ACTIVITIES sa
                        INNER JOIN Latest_HH hh
                            ON hh.client_id = sa.client_id
                            AND hh.rn = 1
                        WHERE sa.TYPE = 'Client'
                        AND sa.STATUS = 'None'
                        AND sa.service_date >= DATEADD(DD, 1, GETDATE()) 
                        AND sa.service_date <= DATEADD(DD, 14, GETDATE())
                        AND (
                            hh.med_end_date <= DATEADD(DAY, 45, GETDATE())
                            OR hh.med_end_date < GETDATE()
                        )
                    `;
                    
                    const result = await pool.request().query(expiringMedicaidQuery);
                    await pool.close();
                    
                    const count = processRows(result.recordset.map(r => ({
                        CLIENT_ID: r.ClientID,
                        CLIENT_NAME: r.ClientName,
                        LOCATION: r.Location
                    })), 'Expiring Medicaid', clientMap);
                    console.log(` Expiring Medicaid: ${result.recordset.length} rows, ${count} clients added`);
                    return { reportName: 'Expiring Medicaid', rows: result.recordset };
                } catch (err) {
                    console.error(' Error fetching Expiring Medicaid:', err.message);
                    return { reportName: 'Expiring Medicaid', rows: [], error: err.message };
                }
            })()
        );
        
        // 3. Weekly Risk Analysis (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    const weeklyRiskSql = `
                        SELECT DISTINCT
                            p.person_id AS client_id,
                            p.last_name || ', ' || p.first_name AS client_name,
                            org.name AS location
                        FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
                        JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = mv_sa.client_id
                        JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = mv_sa.activity_log_id
                        JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
                        WHERE TO_DATE(mv_sa.actual_begin_datetime) >= DATE_TRUNC('week', CURRENT_DATE()) - INTERVAL '1 day'
                          AND TO_DATE(mv_sa.actual_begin_datetime) < DATE_TRUNC('week', CURRENT_DATE()) + INTERVAL '7 days'
                          AND mv_sa.status IN ('Kept', 'DNS', 'CBC', 'CBT')
                    `;
                    
                    connection.execute({
                        sqlText: weeklyRiskSql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error(' Weekly Risk Analysis query error:', err.message);
                                resolve({ reportName: 'Weekly Risk Analysis', rows: [], error: err.message });
                            } else {
                                const count = processRows(rows, 'Weekly Risk Analysis', clientMap);
                                console.log(` Weekly Risk Analysis: ${rows ? rows.length : 0} rows, ${count} clients added`);
                                resolve({ reportName: 'Weekly Risk Analysis', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // 4. Pathway Coordinator (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    const pathwaySql = generateSQLQuery('today', 'kept-sessions');
                    
                    connection.execute({
                        sqlText: pathwaySql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error(' Pathway Coordinator query error:', err.message);
                                resolve({ reportName: 'Pathway Coordinator', rows: [], error: err.message });
                            } else {
                                const count = processRows(rows, 'Pathway Coordinator', clientMap);
                                console.log(` Pathway Coordinator: ${rows ? rows.length : 0} rows, ${count} clients added`);
                                resolve({ reportName: 'Pathway Coordinator', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // 5. Clinical Director Overview (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    const clinicalDirectorSql = generateSQLQuery('today', 'clinical-director');
                    
                    connection.execute({
                        sqlText: clinicalDirectorSql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error(' Clinical Director Overview query error:', err.message);
                                resolve({ reportName: 'Clinical Director Overview', rows: [], error: err.message });
                            } else {
                                const count = processRows(rows, 'Clinical Director Overview', clientMap);
                                console.log(` Clinical Director Overview: ${rows ? rows.length : 0} rows, ${count} clients added`);
                                resolve({ reportName: 'Clinical Director Overview', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // 6. PHQ-9 Report (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    // Use yesterday's date for PHQ-9 (in local timezone)
                    const today = new Date();
                    const yesterday = new Date(today);
                    yesterday.setDate(yesterday.getDate() - 1);
                    // Format as YYYY-MM-DD in local timezone (not UTC)
                    const year = yesterday.getFullYear();
                    const month = String(yesterday.getMonth() + 1).padStart(2, '0');
                    const day = String(yesterday.getDate()).padStart(2, '0');
                    const yesterdayDate = `${year}-${month}-${day}`;
                    console.log(` [PHQ-9 Cross-Report] Using yesterday's date: ${yesterdayDate} (local timezone)`);
                    console.log(` [PHQ-9 Cross-Report] Today's date would be: ${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`);
                    const phq9Sql = `
                        SELECT DISTINCT
                            c.client_id,
                            c.full_name_alternate AS client_name,
                            o.name AS location
                        FROM mv_CLIENT c
                            INNER JOIN client_program cp ON cp.client_id = c.client_id AND cp.LAST_OPERATION <> 'del'
                            INNER JOIN mv_client_document client_doc ON c.client_id = client_doc.client_id 
                                AND client_doc.LAST_OPERATION <> 'del'
                                AND client_doc.deleted <> 'Yes'
                            INNER JOIN mv_impact_data mv_impact ON mv_impact.document_id = client_doc.document_id
                                AND mv_impact.measure IN ('PHQ-9', 'PHQ-9A')
                                AND TO_DATE(mv_impact.service_date) = DATEADD(DAY, -1, CURRENT_DATE())
                                AND mv_impact.last_operation <> 'del'
                            LEFT JOIN staff_organization so ON cp.staff_id = so.staff_id
                            LEFT JOIN organization o ON so.organization_id = o.organization_id
                        WHERE c.LAST_OPERATION <> 'del'
                            AND cp.begin_date IS NOT NULL
                            AND cp.end_date IS NULL
                            AND cp.priority = 1
                            AND c.client_id NOT IN (2324,2325,7262,7264,41734,42342,54302,59113,71109,73459,75821,76370,76392,76401,76402,77659,90059,90473,90498,92655,99819,101751,103382,108967,108989,109657)
                    `;
                    
                    console.log(`[PHQ-9 Cross-Report] Executing query for date: ${yesterdayDate}`);
                    connection.execute({
                        sqlText: phq9Sql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error('[PHQ-9 Cross-Report] Query error:', err.message);
                                console.error('[PHQ-9 Cross-Report] Full error:', err);
                                resolve({ reportName: 'PHQ-9 Report', rows: [], error: err.message });
                            } else {
                                // Debug: Log column names from first row
                                if (rows && rows.length > 0) {
                                    console.log(`[PHQ-9 Cross-Report] First row keys:`, Object.keys(rows[0]));
                                    console.log(`[PHQ-9 Cross-Report] First row sample:`, JSON.stringify(rows[0], null, 2));
                                    // Log the actual client_id value and its type
                                    const firstClientId = rows[0].client_id || rows[0].CLIENT_ID || rows[0]['CLIENT_ID'] || rows[0]['client_id'];
                                    console.log(`[PHQ-9 Cross-Report] First client_id value: ${firstClientId}, type: ${typeof firstClientId}`);
                                }
                                const count = processRows(rows, 'PHQ-9 Report', clientMap);
                                console.log(`[PHQ-9 Cross-Report] Query completed (date: ${yesterdayDate}): ${rows ? rows.length : 0} rows, ${count} clients added`);
                                if (rows && rows.length > 0) {
                                    const sampleIds = rows.slice(0, 5).map(r => {
                                        const id = r.client_id || r.CLIENT_ID || r['CLIENT_ID'] || r['client_id'];
                                        return `${id} (${typeof id})`;
                                    });
                                    console.log(`[PHQ-9 Cross-Report] Sample client IDs found:`, sampleIds);
                                    // Verify these IDs are now in the map
                                    rows.slice(0, 5).forEach(r => {
                                        const id = String(r.client_id || r.CLIENT_ID || r['CLIENT_ID'] || r['client_id'] || '');
                                        if (id && clientMap.has(id)) {
                                            const client = clientMap.get(id);
                                            console.log(`[PHQ-9 Cross-Report] Verified client ${id} in map with reports:`, client.reports);
                                        } else if (id) {
                                            console.log(`[PHQ-9 Cross-Report] WARNING: Client ${id} NOT in map after processRows!`);
                                        }
                                    });
                                }
                                resolve({ reportName: 'PHQ-9 Report', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // 7. GAD-7 Report (Snowflake)
        if (snowflakeReady) {
            queryPromises.push(
                new Promise((resolve, reject) => {
                    // Use yesterday's date for GAD-7 (in local timezone)
                    const today = new Date();
                    const yesterday = new Date(today);
                    yesterday.setDate(yesterday.getDate() - 1);
                    // Format as YYYY-MM-DD in local timezone (not UTC)
                    const year = yesterday.getFullYear();
                    const month = String(yesterday.getMonth() + 1).padStart(2, '0');
                    const day = String(yesterday.getDate()).padStart(2, '0');
                    const yesterdayDate = `${year}-${month}-${day}`;
                    console.log(`[GAD-7 Cross-Report] Using yesterday's date: ${yesterdayDate} (local timezone)`);
                    const gad7Sql = `
                        SELECT DISTINCT
                            c.client_id,
                            c.full_name_alternate AS client_name,
                            o.name AS location
                        FROM mv_CLIENT c
                            INNER JOIN client_program cp ON cp.client_id = c.client_id AND cp.LAST_OPERATION <> 'del'
                            INNER JOIN mv_client_document client_doc ON c.client_id = client_doc.client_id 
                                AND client_doc.LAST_OPERATION <> 'del'
                                AND client_doc.deleted <> 'Yes'
                            INNER JOIN mv_impact_data mv_impact ON mv_impact.document_id = client_doc.document_id
                                AND mv_impact.measure = 'GAD-7'
                                AND TO_DATE(mv_impact.service_date) = DATEADD(DAY, -1, CURRENT_DATE())
                                AND mv_impact.last_operation <> 'del'
                            LEFT JOIN staff_organization so ON cp.staff_id = so.staff_id
                            LEFT JOIN organization o ON so.organization_id = o.organization_id
                        WHERE c.LAST_OPERATION <> 'del'
                            AND cp.begin_date IS NOT NULL
                            AND cp.end_date IS NULL
                            AND cp.priority = 1
                            AND c.client_id NOT IN (2324,2325,7262,7264,41734,42342,54302,59113,71109,73459,75821,76370,76392,76401,76402,77659,90059,90473,90498,92655,99819,101751,103382,108967,108989,109657)
                    `;
                    
                    console.log(`[GAD-7 Cross-Report] Executing query for date: ${yesterdayDate}`);
                    connection.execute({
                        sqlText: gad7Sql,
                        complete: function(err, stmt, rows) {
                            if (err) {
                                console.error('[GAD-7 Cross-Report] Query error:', err.message);
                                console.error('[GAD-7 Cross-Report] Full error:', err);
                                resolve({ reportName: 'GAD-7 Report', rows: [], error: err.message });
                            } else {
                                // Debug: Log column names from first row
                                if (rows && rows.length > 0) {
                                    console.log(`[GAD-7 Cross-Report] First row keys:`, Object.keys(rows[0]));
                                    console.log(`[GAD-7 Cross-Report] First row sample:`, JSON.stringify(rows[0], null, 2));
                                    // Log the actual client_id value and its type
                                    const firstClientId = rows[0].client_id || rows[0].CLIENT_ID || rows[0]['CLIENT_ID'] || rows[0]['client_id'];
                                    console.log(`[GAD-7 Cross-Report] First client_id value: ${firstClientId}, type: ${typeof firstClientId}`);
                                }
                                const count = processRows(rows, 'GAD-7 Report', clientMap);
                                console.log(`[GAD-7 Cross-Report] Query completed (date: ${yesterdayDate}): ${rows ? rows.length : 0} rows, ${count} clients added`);
                                if (rows && rows.length > 0) {
                                    const sampleIds = rows.slice(0, 5).map(r => {
                                        const id = r.client_id || r.CLIENT_ID || r['CLIENT_ID'] || r['client_id'];
                                        return `${id} (${typeof id})`;
                                    });
                                    console.log(`[GAD-7 Cross-Report] Sample client IDs found:`, sampleIds);
                                    // Verify these IDs are now in the map
                                    rows.slice(0, 5).forEach(r => {
                                        const id = String(r.client_id || r.CLIENT_ID || r['CLIENT_ID'] || r['client_id'] || '');
                                        if (id && clientMap.has(id)) {
                                            const client = clientMap.get(id);
                                            console.log(`[GAD-7 Cross-Report] Verified client ${id} in map with reports:`, client.reports);
                                        } else if (id) {
                                            console.log(`[GAD-7 Cross-Report] WARNING: Client ${id} NOT in map after processRows!`);
                                        }
                                    });
                                }
                                resolve({ reportName: 'GAD-7 Report', rows: rows || [] });
                            }
                        }
                    });
                })
            );
        }
        
        // Execute all queries in parallel and wait for all to complete
        console.log(`Executing ${queryPromises.length} queries in parallel...`);
        const results = await Promise.allSettled(queryPromises);
        
        const endTime = Date.now();
        const duration = ((endTime - startTime) / 1000).toFixed(2);
        console.log(`All queries completed in ${duration} seconds (parallel execution)`);
        
        // Log any failures
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                console.error(` Query ${index + 1} failed:`, result.reason);
            } else if (result.value && result.value.error) {
                console.error(` Query ${index + 1} (${result.value.reportName}) had error:`, result.value.error);
            }
        });
        
        // Debug: Check if PHQ-9/GAD-7 client IDs are in the map
        const allClientIds = Array.from(clientMap.keys());
        console.log(`[Client Cross-Report] Total unique client IDs in map: ${allClientIds.length}`);
        
        // Check for PHQ-9/GAD-7 specific client IDs (from the sample we logged earlier)
        const phq9SampleIds = ['98287']; // From the terminal output the user showed
        phq9SampleIds.forEach(id => {
            if (clientMap.has(id)) {
                const client = clientMap.get(id);
                console.log(`[Client Cross-Report] Client ${id} in map has reports:`, client.reports);
            } else {
                console.log(`[Client Cross-Report] WARNING: Client ${id} NOT found in map!`);
                // Try variations
                const variations = [String(id), Number(id), `0${id}`, `${id}.0`];
                variations.forEach(v => {
                    if (clientMap.has(String(v))) {
                        console.log(`[Client Cross-Report] Found client ${id} as variation: ${v}`);
                    }
                });
            }
        });
        
        // Debug: Check clientMap before converting
        const phq9InMap = Array.from(clientMap.entries()).filter(([id, data]) => 
            data.reports && data.reports.includes('PHQ-9 Report')
        );
        const gad7InMap = Array.from(clientMap.entries()).filter(([id, data]) => 
            data.reports && data.reports.includes('GAD-7 Report')
        );
        console.log(`[Client Cross-Report] Before conversion - clientMap has ${clientMap.size} entries`);
        console.log(`[Client Cross-Report] PHQ-9 clients in map: ${phq9InMap.length}`);
        console.log(`[Client Cross-Report] GAD-7 clients in map: ${gad7InMap.length}`);
        if (phq9InMap.length > 0) {
            const sample = phq9InMap[0];
            console.log(`[Client Cross-Report] Sample PHQ-9 client in map:`, {
                clientId: sample[0],
                clientName: sample[1].clientName,
                reports: sample[1].reports
            });
        }
        
        // Convert map to array and sort
        const clients = Array.from(clientMap.entries()).map(([clientId, data]) => {
            // Debug: Log if this client has PHQ-9/GAD-7
            const hasPhq9 = data.reports && data.reports.includes('PHQ-9 Report');
            const hasGad7 = data.reports && data.reports.includes('GAD-7 Report');
            if (hasPhq9 || hasGad7) {
                console.log(`[Client Cross-Report] Converting client ${clientId} with reports:`, data.reports);
            }
            return {
                clientId,
                clientName: data.clientName,
                reports: data.reports.sort(),
                reportCount: data.reports.length,
                locations: data.locations.sort()
            };
        }).sort((a, b) => {
            // Sort by report count (desc), then by client name
            if (b.reportCount !== a.reportCount) {
                return b.reportCount - a.reportCount;
            }
            return a.clientName.localeCompare(b.clientName);
        });
        
        // Debug: Check clients array after conversion
        const phq9InClients = clients.filter(c => c.reports && c.reports.includes('PHQ-9 Report'));
        const gad7InClients = clients.filter(c => c.reports && c.reports.includes('GAD-7 Report'));
        console.log(`[Client Cross-Report] After conversion - clients array has ${clients.length} entries`);
        console.log(`[Client Cross-Report] PHQ-9 clients in array: ${phq9InClients.length}`);
        console.log(`[Client Cross-Report] GAD-7 clients in array: ${gad7InClients.length}`);
        
        // Count clients by report source for summary
        const reportCounts = {
            'Yearly Medical Examination Report': 0,
            'Expiring Medicaid': 0,
            'Weekly Risk Analysis': 0,
            'Pathway Coordinator': 0,
            'Clinical Director Overview': 0,
            'PHQ-9 Report': 0,
            'GAD-7 Report': 0
        };
        
        clients.forEach(client => {
            client.reports.forEach(report => {
                if (reportCounts.hasOwnProperty(report)) {
                    reportCounts[report]++;
                }
            });
        });
        
        console.log(` Client Cross-Report: ${clients.length} unique clients found`);
        console.log(` Clients by report source:`);
        console.log(`   Yearly Medical Examination Report: ${reportCounts['Yearly Medical Examination Report']} clients`);
        console.log(`   Expiring Medicaid: ${reportCounts['Expiring Medicaid']} clients`);
        console.log(`   Weekly Risk Analysis: ${reportCounts['Weekly Risk Analysis']} clients`);
        console.log(`   Pathway Coordinator: ${reportCounts['Pathway Coordinator']} clients`);
        console.log(`   Clinical Director Overview: ${reportCounts['Clinical Director Overview']} clients`);
        console.log(`   PHQ-9 Report: ${reportCounts['PHQ-9 Report']} clients`);
        console.log(`   GAD-7 Report: ${reportCounts['GAD-7 Report']} clients`);
        
        // Count clients appearing in multiple reports
        const multiReportClients = clients.filter(c => c.reportCount > 1);
        console.log(`📈 Clients appearing in multiple reports: ${multiReportClients.length}`);
        if (multiReportClients.length > 0) {
            const byCount = {};
            multiReportClients.forEach(c => {
                byCount[c.reportCount] = (byCount[c.reportCount] || 0) + 1;
            });
            console.log(`   Breakdown: ${Object.entries(byCount).map(([count, num]) => `${num} clients in ${count} reports`).join(', ')}`);
        }
        
        if (clients.length === 0) {
            console.log(' Warning: No clients found in cross-report. This could mean:');
            console.log('   - All data sources returned empty results');
            console.log('   - Snowflake connection not ready (check snowflakeReady status)');
            console.log('   - SQL Server connection issues');
            console.log('   - No clients match the report criteria');
        }
        
        // Log PHQ-9 and GAD-7 clients in final response
        const phq9Clients = clients.filter(c => c.reports.includes('PHQ-9 Report'));
        const gad7Clients = clients.filter(c => c.reports.includes('GAD-7 Report'));
        console.log(`[Client Cross-Report] Final response - PHQ-9 clients: ${phq9Clients.length}, GAD-7 clients: ${gad7Clients.length}`);
        if (phq9Clients.length > 0) {
            console.log(`[Client Cross-Report] Sample PHQ-9 clients in response:`, phq9Clients.slice(0, 5).map(c => ({ id: c.clientId, name: c.clientName, reports: c.reports })));
        }
        if (gad7Clients.length > 0) {
            console.log(`[Client Cross-Report] Sample GAD-7 clients in response:`, gad7Clients.slice(0, 5).map(c => ({ id: c.clientId, name: c.clientName, reports: c.reports })));
        }
        
        const responseData = {
            data: clients,
            totalClients: clients.length,
            reportNames: ['Yearly Medical Examination Report', 'Expiring Medicaid', 'Weekly Risk Analysis', 'Pathway Coordinator', 'Clinical Director Overview', 'PHQ-9 Report', 'GAD-7 Report'],
            generated: new Date().toISOString()
        };
        
        // Cache the response (even if empty)
        clientCrossReportCache = responseData;
        clientCrossReportCacheTime = Date.now();
        console.log('Cached client cross-report data (will expire in 5 minutes)');
        console.log(`   Total clients: ${clients.length}`);
        console.log(`   Snowflake ready: ${snowflakeReady}`);
        
        return responseData;
        
    } catch (err) {
        console.error(' Error in client cross-report:', err);
        throw err; // Re-throw to let caller handle
    }
}

// Background refresh function - runs periodically to keep cache fresh
async function refreshClientCrossReportCache() {
    // Check if Snowflake is ready before attempting refresh
    if (!snowflakeReady) {
        console.log(' Background refresh: Skipping - Snowflake not ready yet');
        return;
    }
    
    try {
        console.log(' Background refresh: Updating client cross-report cache...');
        await fetchClientCrossReportData();
        console.log(' Background refresh: Client cross-report cache updated successfully');
    } catch (err) {
        console.error(' Background refresh: Failed to update client cross-report cache:', err.message);
        // Don't throw - we want the interval to continue even if one refresh fails
    }
}

// Start background refresh interval
function startClientCrossReportBackgroundRefresh() {
    console.log(' Starting client cross-report background refresh service...');
    
    // Wait for Snowflake to be ready before initial fetch
    // Check every 2 seconds until Snowflake is ready
    const checkSnowflakeReady = setInterval(() => {
        if (snowflakeReady) {
            clearInterval(checkSnowflakeReady);
            console.log(' Snowflake is ready - starting initial client cross-report fetch...');
            refreshClientCrossReportCache();
        } else {
            console.log('Waiting for Snowflake connection before starting client cross-report refresh...');
        }
    }, 2000);
    
    // Set up periodic refresh (every 4 minutes)
    // This will start immediately, but the refresh function will check snowflakeReady
    clientCrossReportRefreshInterval = setInterval(() => {
        refreshClientCrossReportCache();
    }, CLIENT_CROSS_REPORT_REFRESH_INTERVAL);
    
    console.log(` Client cross-report will auto-refresh every ${CLIENT_CROSS_REPORT_REFRESH_INTERVAL / 1000 / 60} minutes (once Snowflake is ready)`);
}

// Get clients across all reports - shows which reports each client appears in
app.get('/api/client-cross-report', requireAuth, async (req, res) => {
    console.log('========================================');
    console.log(' [API ENDPOINT CALLED] Fetching clients across all reports...');
    console.log(`[API Endpoint] Request URL: ${req.url}`);
    console.log(`[API Endpoint] Query params: ${JSON.stringify(req.query)}`);
    console.log(`[API Endpoint] Timestamp: ${new Date().toISOString()}`);
    console.log('========================================');
    
    // Check for force_refresh parameter
    const forceRefresh = req.query.force_refresh === 'true';
    console.log(`[API Endpoint] Force refresh requested: ${forceRefresh}`);
    
    // Check cache first (unless force_refresh is requested)
    const cacheCheckTime = Date.now();
    const cacheIsValid = !forceRefresh && clientCrossReportCache && clientCrossReportCacheTime && (cacheCheckTime - clientCrossReportCacheTime) < CLIENT_CROSS_REPORT_CACHE_TTL;
    
    if (cacheIsValid) {
        // Always verify cache has PHQ-9/GAD-7 data
        const phq9InCache = clientCrossReportCache.data.filter(c => c.reports && Array.isArray(c.reports) && c.reports.includes('PHQ-9 Report'));
        const gad7InCache = clientCrossReportCache.data.filter(c => c.reports && Array.isArray(c.reports) && c.reports.includes('GAD-7 Report'));
        
        console.log(`[API Endpoint] Cache check: ${clientCrossReportCache.data.length} clients, PHQ-9: ${phq9InCache.length}, GAD-7: ${gad7InCache.length}`);
        
        // If cache doesn't have PHQ-9/GAD-7, force fresh fetch
        if (phq9InCache.length === 0 || gad7InCache.length === 0) {
            console.log(`[API Endpoint] Cache missing PHQ-9/GAD-7 - forcing fresh fetch`);
            // Fall through to fetch fresh data
        } else {
            console.log(`[API Endpoint] Returning valid cache with PHQ-9/GAD-7 data`);
            return res.json(clientCrossReportCache);
        }
    }
    
    // Cache expired, doesn't exist, or force_refresh requested - fetch fresh data
    if (forceRefresh) {
        console.log(' Force refresh requested - fetching fresh data...');
    } else {
        console.log(' Cache expired or missing - fetching fresh data...');
    }
    try {
        const responseData = await fetchClientCrossReportData();
        
        // Debug: Verify what we're about to send
        const phq9InResponse = responseData.data.filter(c => c.reports && c.reports.includes('PHQ-9 Report'));
        const gad7InResponse = responseData.data.filter(c => c.reports && c.reports.includes('GAD-7 Report'));
        console.log(`[API Endpoint] About to send response with ${responseData.data.length} clients`);
        console.log(`[API Endpoint] PHQ-9 clients in response: ${phq9InResponse.length}`);
        console.log(`[API Endpoint] GAD-7 clients in response: ${gad7InResponse.length}`);
        if (phq9InResponse.length > 0) {
            console.log(`[API Endpoint] Sample PHQ-9 client being sent:`, JSON.stringify({
                clientId: phq9InResponse[0].clientId,
                clientName: phq9InResponse[0].clientName,
                reports: phq9InResponse[0].reports
            }, null, 2));
        }
        
        res.json(responseData);
    } catch (err) {
        console.error(' Error in client cross-report endpoint:', err);
        res.status(500).json({ 
            error: 'Failed to fetch client cross-report data',
            details: err.message 
        });
    }
});

// Pathway Coordinator endpoint
app.get('/api/pathway-coordinator', requireAuth, requireSnowflakeReady, (req, res) => {
    const dateParam = req.query.date || 'today';
    const dateSelection = dateParam === 'yesterday' ? 'yesterday' : 'today';
    
    console.log(`Fetching pathway coordinator data for date: ${dateSelection}`);
    
    const sqlQuery = generateSQLQuery(dateSelection, 'kept-sessions');
    
    connection.execute({
        sqlText: sqlQuery,
        complete: function(err, stmt, rows) {
            if (err) {
                console.error('Pathway Coordinator query error:', err.message);
                return res.status(500).json({ 
                    error: 'Failed to fetch pathway coordinator data',
                    details: err.message 
                });
            }
            
            console.log(`Pathway Coordinator query returned ${rows ? rows.length : 0} rows`);
            
            // Format the response to match what the frontend expects
            const responseData = {
                data: rows || [],
                total: rows ? rows.length : 0,
                date: dateSelection
            };
            
            res.json(responseData);
        }
    });
});

// Debug endpoint to check cache contents
app.get('/api/client-cross-report-debug', requireAuth, (req, res) => {
    if (!clientCrossReportCache) {
        return res.json({ 
            cacheExists: false,
            message: 'Cache does not exist yet'
        });
    }
    
    const phq9InCache = clientCrossReportCache.data.filter(c => c.reports && c.reports.includes('PHQ-9 Report'));
    const gad7InCache = clientCrossReportCache.data.filter(c => c.reports && c.reports.includes('GAD-7 Report'));
    
    // Get a sample PHQ-9 client
    const samplePhq9 = phq9InCache.length > 0 ? {
        clientId: phq9InCache[0].clientId,
        clientName: phq9InCache[0].clientName,
        reports: phq9InCache[0].reports
    } : null;
    
    res.json({
        cacheExists: true,
        cacheCreated: new Date(clientCrossReportCacheTime).toISOString(),
        totalClients: clientCrossReportCache.data.length,
        phq9Clients: phq9InCache.length,
        gad7Clients: gad7InCache.length,
        samplePhq9Client: samplePhq9,
        allReportNames: Array.from(new Set(clientCrossReportCache.data.flatMap(c => c.reports || [])))
    });
});

// API endpoint to create a Zoom meeting
// Note: Auth removed for now since Chrome extension doesn't have token system
// You can add it back by changing to: app.post('/api/create-zoom-meeting', requireAuth, async (req, res) => {
app.post('/api/create-zoom-meeting', async (req, res) => {
    try {
        const { topic, duration, start_time, timezone, settings, staff_info, client_info } = req.body;
        
        console.log('Creating Zoom meeting with options:', { topic, duration, start_time, settings });
        if (staff_info) {
            console.log('Staff info:', staff_info);
        }
        if (client_info) {
            console.log('Client info:', client_info);
        }
        
        // Build meeting description with staff and client info
        let description = '';
        if (client_info && client_info.name) {
            description += `Client: ${client_info.name}`;
            if (client_info.id) {
                description += ` (ID: ${client_info.id})`;
            }
            description += '\n';
        }
        if (staff_info && staff_info.name) {
            description += `Staff: ${staff_info.name}`;
            if (staff_info.id) {
                description += ` (ID: ${staff_info.id})`;
            }
        }
        
        const meetingOptions = {
            topic: topic || 'Carelogic Meeting',
            duration: duration || 30,
            start_time: start_time || null,
            timezone: timezone || null,
            description: description || null,
            settings: settings || {}
        };
        
        const meeting = await createMeeting(meetingOptions);
        
        console.log(' Zoom meeting created successfully:');
        console.log('  Meeting ID:', meeting.meeting_id);
        console.log('  Join URL:', meeting.join_url);
        console.log('  Start URL:', meeting.start_url);
        console.log('  Topic:', meeting.topic);
        console.log('  Password:', meeting.password);
        console.log('  Request details:');
        console.log('    Topic:', topic);
        console.log('    Start time:', start_time);
        console.log('    Duration:', duration);
        
        // Check if this is a duplicate meeting ID (check both session and a global cache)
        const previousMeetingId = req.session?.lastMeetingId;
        if (previousMeetingId && previousMeetingId === meeting.meeting_id) {
            console.error(' ERROR: Same meeting ID returned as previous meeting!');
            console.error('   Previous Meeting ID:', previousMeetingId);
            console.error('   Current Meeting ID:', meeting.meeting_id);
            console.error('   Join URL:', meeting.join_url);
            console.error('   This indicates Zoom may be reusing meetings - this should NOT happen!');
            
            // Return error to prevent using duplicate meeting
            return res.status(500).json({
                success: false,
                error: 'Duplicate meeting ID detected. Zoom returned the same meeting ID as a previous meeting.',
                details: `Meeting ID ${meeting.meeting_id} was already used. Please try again.`,
                meeting_id: meeting.meeting_id
            });
        }
        
        // Store meeting ID in session for comparison
        if (!req.session) req.session = {};
        req.session.lastMeetingId = meeting.meeting_id;
        
        // Also store in a simple in-memory cache (last 10 meetings) to catch duplicates across sessions
        if (!global.recentMeetingIds) {
            global.recentMeetingIds = [];
        }
        if (global.recentMeetingIds.includes(meeting.meeting_id)) {
            console.error(' ERROR: Duplicate meeting ID found in global cache!');
            console.error('   Meeting ID:', meeting.meeting_id);
            console.error('   Recent meeting IDs:', global.recentMeetingIds);
            
            return res.status(500).json({
                success: false,
                error: 'Duplicate meeting ID detected in recent meetings.',
                details: `Meeting ID ${meeting.meeting_id} was recently used. Please try again.`,
                meeting_id: meeting.meeting_id
            });
        }
        
        // Add to cache (keep last 10)
        global.recentMeetingIds.push(meeting.meeting_id);
        if (global.recentMeetingIds.length > 10) {
            global.recentMeetingIds.shift();
        }
        
        res.json({
            success: true,
            join_url: meeting.join_url,
            meeting_id: meeting.meeting_id,
            password: meeting.password,
            topic: meeting.topic,
            start_url: meeting.start_url
        });
    } catch (error) {
        console.error('Error creating Zoom meeting:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to create Zoom meeting',
            details: error.message 
        });
    }
});

// Test endpoint to schedule a test email (for testing database)
app.post('/api/test-schedule-email', async (req, res) => {
    try {
        const { to, subject, text, html, scheduleFor } = req.body;
        
        if (!to || !scheduleFor) {
            return res.status(400).json({
                success: false,
                error: 'to and scheduleFor are required'
            });
        }
        
        const scheduleDate = new Date(scheduleFor);
        const now = new Date();
        
        if (scheduleDate <= now) {
            return res.status(400).json({
                success: false,
                error: 'scheduleFor must be in the future'
            });
        }
        
        const emailData = {
            to: to,
            subject: subject || 'Test Email',
            text: text || 'This is a test email.',
            html: html || '<p>This is a test email.</p>',
            icsContent: req.body.icsContent || null
        };
        
        const result = scheduleEmail(emailData, scheduleDate);
        
        res.json({
            success: true,
            message: 'Test email scheduled successfully',
            ...result
        });
    } catch (error) {
        console.error('Error scheduling test email:', error);
        res.status(500).json({
            success: false,
            error: error.message || 'Failed to schedule test email'
        });
    }
});

// Catch-all route for 404 errors - log what's being requested
app.use((req, res) => {
    console.log(`[404] Requested resource not found: ${req.method} ${req.url}`);
    res.status(404).json({ 
        error: 'Not found',
        path: req.url,
        method: req.method
    });
});

const PORT = process.env.PORT || 4500
const server = app.listen(PORT, () => {
    console.log(`API server listening on port ${PORT}`);
});

// WebSocket server (now uses live Snowflake data)
const wss = new WebSocket.Server({ server });
console.log(' WebSocket server created and attached to HTTP server');

// Global state to track all connected clients
let allClients = new Map(); // Changed to Map to store client preferences
let currentView = 'kept-sessions';
let lastQueryTime = 0;
let cachedDataToday = null;
let cachedDataYesterday = null;
let cachedDirectorToday = null;
let cachedWeeklyRisk = null; // Cache for weekly risk analysis
let lastWeeklyRiskQueryTime = 0;

// Function to generate SQL query based on date selection and view type
function generateSQLQuery(dateSelection = 'today', viewType = 'kept-sessions') {
    const isToday = dateSelection === 'today';
    const targetDate = isToday ? 'CURRENT_DATE()' : 'DATEADD(day, -1, CURRENT_DATE())';
    const beforeTargetDate = isToday ? 'CURRENT_DATE()' : 'DATEADD(day, -2, CURRENT_DATE())';
    
    // Clinical Director view uses the same query as Pathway dashboard but shows both kept and non-kept
    if (viewType === 'clinical-director') {
        return `
      /* Simplified Clinical Director query - show today's appointments */
      SELECT DISTINCT
        org.name AS Location,
        mv_sa.activity_log_id,
        staff.staff_id,
        staff.full_name AS Staff,
        p.person_id,
        p.last_name,
        p.first_name,
        COALESCE(ad.actual_end_datetime, mv_sa.actual_begin_datetime) AS ACTUAL_END_DATETIME,
        COALESCE(ad.status, 'Scheduled') AS appointment_status
      FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
      JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = mv_sa.client_id
      JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = mv_sa.staff_id
      JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = mv_sa.activity_log_id
      JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
      LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
        ON ad.activity_log_id = mv_sa.activity_log_id
       AND TO_DATE(ad.actual_begin_datetime) = ${targetDate}
      LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
      WHERE TO_DATE(mv_sa.actual_begin_datetime) = ${targetDate}
        AND UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
        AND COALESCE(ad.status, 'Scheduled') != 'Error'
      ORDER BY org.name, ACTUAL_END_DATETIME ASC;
    `;
    }

    // Helper in-scope for coordinator WHERE building
    const coordinatorStatusPrefix = viewType === 'kept-sessions' ? "ad.status = 'Kept' AND " : '';
    
    return `
      WITH pathway_starters AS (
          SELECT 
              ad_pathway.client_id,
              staff_pathway.full_name AS pathway_started_by,
              ROW_NUMBER() OVER (PARTITION BY ad_pathway.client_id ORDER BY ad_pathway.actual_end_datetime DESC) AS rn
          FROM CARELOGIC_PROD.SECURE.activity_detail ad_pathway
          JOIN CARELOGIC_PROD.SECURE.activity_log al_pathway ON ad_pathway.ACTIVITY_LOG_ID = al_pathway.ACTIVITY_LOG_ID
          JOIN CARELOGIC_PROD.SECURE.mv_staff staff_pathway ON staff_pathway.staff_id = ad_pathway.status_by
          WHERE al_pathway.activity_id = 1688
          AND ad_pathway.status = 'Kept'
          AND TO_DATE(ad_pathway.actual_end_datetime) = ${targetDate}
      )
      SELECT 
        org.name AS Location,
        staff.staff_id,
        staff.full_name AS Staff,
        p.person_id,
        p.last_name,
        p.first_name,
        ad.ACTUAL_END_DATETIME,
        CASE 
            WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad2
                JOIN CARELOGIC_PROD.SECURE.activity_log al2 ON ad2.ACTIVITY_LOG_ID = al2.ACTIVITY_LOG_ID
                WHERE ad2.client_id = p.person_id
                AND al2.activity_id = 1688
                AND ad2.status = 'Kept'
                AND TO_DATE(ad2.actual_end_datetime) = ${targetDate}
            ) THEN 'Created'
            ELSE 'Not Created'
        END AS PATHWAYSTATUS,
        ps.pathway_started_by AS PATHWAY_STARTED_BY,
        CASE 
            WHEN EXISTS (
                SELECT 1 FROM CARELOGIC_PROD.SECURE.activity_detail ad2
                JOIN CARELOGIC_PROD.SECURE.activity_log al2 ON ad2.ACTIVITY_LOG_ID = al2.ACTIVITY_LOG_ID
                JOIN CARELOGIC_PROD.SECURE.document doc2 ON doc2.activity_detail_id = ad2.activity_detail_id
                WHERE ad2.client_id = p.person_id
                AND al2.activity_id = 1688
                AND ad2.status = 'Kept'
                AND TO_DATE(ad2.actual_end_datetime) = ${targetDate}
                AND doc2.FULLY_SIGNED_YN = 'Yes'
            ) THEN 'Yes'
            ELSE 'No'
        END AS FULLY_SIGNED_YN
      FROM CARELOGIC_PROD.SECURE.activity_detail ad
      JOIN CARELOGIC_PROD.SECURE.person p ON p.person_id = ad.client_id
      JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON staff.staff_id = ad.status_by
      JOIN CARELOGIC_PROD.SECURE.activity_log al ON al.activity_log_id = ad.activity_log_id
      LEFT JOIN CARELOGIC_PROD.SECURE.activity act ON al.activity_id = act.activity_id
      JOIN CARELOGIC_PROD.SECURE.organization org ON org.organization_id = al.organization_id
      LEFT JOIN pathway_starters ps ON ps.client_id = p.person_id AND ps.rn = 1
      WHERE ad.status = 'Kept' 
        AND TO_DATE(ad.actual_end_datetime) = ${targetDate}
        AND UPPER(COALESCE(act.description, '')) NOT LIKE '%CCBHC CLINICAL PATHWAY COORDINATION%'
        AND (
            /* a) Clients with signed intake within last 30 days */
            ad.client_id IN (
                SELECT DISTINCT cd.client_id
                FROM mv_client_document cd
                WHERE cd.document_name IN ('IDCC Intake', 'CCBHC Intake', 'IDCC Brief Intake')
                  AND cd.first_signed = 'Yes'
                  AND cd.deleted <> 'Yes'
                  AND TO_DATE(cd.first_signed_date) >= DATEADD(day, -30, CURRENT_DATE())
            )
            OR
            /* b) Clients with CCB-IN3 appointment scheduled for target date without signed intake */
            EXISTS (
                SELECT 1
                FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa2
                WHERE mv_sa2.client_id = p.person_id
                  AND TO_DATE(mv_sa2.actual_begin_datetime) = ${targetDate}
                  AND UPPER(mv_sa2.activity_code) LIKE '%CCB-IN3%'
                  AND mv_sa2.status IN ('Kept', 'None')
                  AND mv_sa2.last_operation <> 'del'
                  /* AND they don't have a signed intake */
                  AND NOT EXISTS (
                      SELECT 1 FROM mv_client_document cd2
                      WHERE cd2.client_id = mv_sa2.client_id
                        AND cd2.document_name IN ('IDCC Intake', 'CCBHC Intake', 'IDCC Brief Intake')
                        AND cd2.first_signed = 'Yes'
                        AND cd2.deleted <> 'Yes'
                  )
            )
        )
        /* Exclude clients who already have completed Clinical Pathway Coordination Note */
        AND p.person_id NOT IN (
              SELECT DISTINCT client_id
              FROM mv_scheduled_activities mv_sa_filter
              WHERE mv_sa_filter.document = 'Clinical Pathway Coordination Note'
                AND mv_sa_filter.status = 'Kept'
                AND TO_DATE(mv_sa_filter.actual_begin_datetime) <= ${targetDate}
        )
      ORDER BY org.name, ad.ACTUAL_END_DATETIME ASC;
    `;
}

// Function to execute query for a specific date and cache the results
async function executeQueryForDate(dateSelection = 'today', viewType = 'kept-sessions') {
    // Check if Snowflake is ready before executing queries
    if (!snowflakeReady) {
        console.log(` Skipping query for ${dateSelection} (${viewType}) - Snowflake not ready yet`);
        return;
    }
    
    console.log(`Executing query for ${dateSelection} (${viewType})...`);
    console.log('Current date for query:', new Date().toISOString().split('T')[0]);
    
    // Generate SQL query based on date selection and view type
    const sql = generateSQLQuery(dateSelection, viewType);
    
    // Define targetDate for debug logging
    const isToday = dateSelection === 'today';
    const targetDate = isToday ? 'CURRENT_DATE()' : 'DATEADD(day, -1, CURRENT_DATE())';
    
    console.log('\n' + '='.repeat(80));
    console.log(`EXECUTING QUERY FOR ${dateSelection.toUpperCase()}`);
    console.log('='.repeat(80));
    console.log(` Target Date: ${targetDate}`);
    console.log(` Current Date: ${new Date().toISOString().split('T')[0]}`);
    console.log(' SQL Query:');
    console.log(sql);
    console.log('='.repeat(80));
    
    // Execute the main query
    connection.execute({
        sqlText: sql,
        complete: function(err, stmt, rows) {
            if (err) {
                console.error(' SQL QUERY ERROR:', err);
                console.log('='.repeat(80));
                // Send error to all clients
                allClients.forEach((clientPrefs, client) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify({ view: currentView, error: 'Query failed.' }));
                    }
                });
            } else {
                console.log(` QUERY SUCCESSFUL - Returned ${rows.length} rows`);
                console.log('='.repeat(80));
                
                if (rows.length > 0) {
                    console.log(' SAMPLE DATA (first 3 rows):');
                    rows.slice(0, 3).forEach((row, index) => {
                        console.log(`\nRow ${index + 1}:`);
                        console.log(JSON.stringify(row, null, 2));
                    });
                    
                    console.log('\n ALL COLUMNS IN RESULTS:');
                    console.log(Object.keys(rows[0]));
                    
                    console.log('\n SUMMARY:');
                    console.log(`- Total rows: ${rows.length}`);
                    console.log(`- Location values: ${[...new Set(rows.map(r => r.Location))].join(', ')}`);
                    console.log(`- Staff count: ${[...new Set(rows.map(r => r.Staff))].length} unique staff`);
                    console.log(`- Pathway Status: ${[...new Set(rows.map(r => r.PathwayStatus))].join(', ')}`);
                } else {
                    console.log(' NO DATA FOUND - Query returned 0 rows');
                }
                
                console.log('='.repeat(80));
                
                const converted = rows.map(row => ({
                    ...row,
                    ACTUAL_END_DATETIME: toESTString(row.ACTUAL_END_DATETIME)
                }));
                
                console.log(` SENDING ${converted.length} rows to WebSocket clients`);
                console.log('='.repeat(80) + '\n');
                
                // Cache data by date and view
                if (viewType === 'clinical-director') {
                    if (dateSelection === 'today') cachedDirectorToday = converted;
                } else {
                    if (dateSelection === 'today') {
                        cachedDataToday = converted;
                    } else {
                        cachedDataYesterday = converted;
                    }
                }
                lastQueryTime = Date.now();
                
                // Send to clients who are interested in this date and view
                allClients.forEach((clientPrefs, client) => {
                    if (client.readyState === WebSocket.OPEN && clientPrefs.date === dateSelection && clientPrefs.view === viewType) {
                        console.log(` Sending data to client (${clientPrefs.date}/${clientPrefs.view})`);
                        client.send(JSON.stringify({ view: viewType, data: converted }));
                    }
                });
            }
        }
    });
}

// Function to refresh weekly risk data
async function refreshWeeklyRiskData() {
    console.log('Refreshing weekly risk data...');
    
    const weeklyRiskQuery = `
        WITH week_schedule AS (
            -- Get all scheduled appointments for current week (Monday to Sunday)
            SELECT 
                mv_sa.client_id,
                mv_sa.staff_id,
                mv_sa.actual_begin_datetime AS scheduled_datetime,
                TO_DATE(mv_sa.actual_begin_datetime) AS scheduled_date,
                DAYOFWEEK(mv_sa.actual_begin_datetime) AS day_of_week,
                DAYNAME(mv_sa.actual_begin_datetime) AS day_name
            FROM CARELOGIC_PROD.SECURE.mv_scheduled_activities mv_sa
            WHERE TO_DATE(mv_sa.actual_begin_datetime) BETWEEN CURRENT_DATE() AND DATEADD(day, 30, CURRENT_DATE())
        )
        -- Rest of query same as /api/weekly-risk-analysis endpoint
        SELECT 
            ws.client_id AS PERSON_ID,
            p.first_name AS FIRST_NAME,
            p.last_name AS LAST_NAME,
            org.name AS LOCATION,
            ws.staff_id AS STAFF_ID,
            staff.full_name AS STAFF_NAME,
            ws.scheduled_datetime AS SCHEDULED_DATETIME,
            ws.scheduled_date AS SCHEDULED_DATE,
            ws.day_of_week AS DAY_OF_WEEK,
            ws.day_name AS DAY_NAME,
            COALESCE(ad.status, 'Scheduled') AS APPOINTMENT_STATUS,
            CASE 
                WHEN ad.status = 'Kept' THEN 'Kept'
                WHEN ad.status IN ('DNS', 'CBC', 'CBT') THEN ad.status
                ELSE 'Scheduled'
            END AS ACTUAL_STATUS,
            'Medium' AS RISK_LEVEL,
            50 AS RISK_SCORE,
            0.5 AS EFFECTIVE_ATTENDANCE_RATE
        FROM week_schedule ws
        JOIN CARELOGIC_PROD.SECURE.person p ON ws.client_id = p.person_id
        LEFT JOIN CARELOGIC_PROD.SECURE.activity_detail ad 
            ON ws.client_id = ad.client_id 
            AND TO_DATE(ad.actual_begin_datetime) = ws.scheduled_date
        LEFT JOIN CARELOGIC_PROD.SECURE.mv_staff staff ON ws.staff_id = staff.staff_id
        LEFT JOIN CARELOGIC_PROD.SECURE.activity_log al ON ad.activity_log_id = al.activity_log_id
        LEFT JOIN CARELOGIC_PROD.SECURE.organization org ON al.organization_id = org.organization_id
        ORDER BY ws.scheduled_datetime;
    `;
    
    return new Promise((resolve, reject) => {
        connection.execute({
            sqlText: weeklyRiskQuery,
            complete: function(err, stmt, rows) {
                if (err) {
                    console.error(' Weekly risk query error:', err);
                    reject(err);
                } else {
                    console.log(` Weekly risk query returned ${rows.length} rows`);
                    
                    // Cache the data
                    cachedWeeklyRisk = {
                        appointments: rows,
                        summary: {
                            total_appointments: rows.length,
                            generated_at: new Date().toISOString()
                        }
                    };
                    lastWeeklyRiskQueryTime = Date.now();
                    
                    // Broadcast to all clients listening for weekly-risk
                    allClients.forEach((clientPrefs, client) => {
                        if (client.readyState === WebSocket.OPEN && clientPrefs.view === 'weekly-risk') {
                            console.log(` Broadcasting weekly-risk update to client`);
                            client.send(JSON.stringify({ view: 'weekly-risk', data: cachedWeeklyRisk }));
                        }
                    });
                    
                    resolve(cachedWeeklyRisk);
                }
            }
        });
    });
}

// Function to refresh both today and yesterday data
async function refreshBothDatasets() {
    if (!snowflakeReady) {
        console.log(' Skipping data refresh - Snowflake not ready yet');
        return;
    }
    
    console.log('Refreshing all datasets...');
    
    try {
        await Promise.all([
            executeQueryForDate('today'),
            executeQueryForDate('yesterday'),
            // Preload Clinical Director (today-only)
            executeQueryForDate('today', 'clinical-director'),
            // Refresh weekly risk data
            refreshWeeklyRiskData()
        ]);
        console.log(' All datasets refreshed successfully');
    } catch (error) {
        console.error(' Error refreshing datasets:', error.message);
    }
}

// Single global interval - refreshes both datasets every 5 minutes
const globalInterval = setInterval(() => {
    refreshBothDatasets();
}, 5 * 60 * 1000); // 5 minutes = 300,000 milliseconds

wss.on('connection', ws => {
    console.log(' WebSocket connection event triggered');
    console.log(`WebSocket client connected. Total clients: ${allClients.size + 1}`);
    
    // Add client to map with default preferences
    allClients.set(ws, { date: 'today', view: 'kept-sessions' });
    
    // Helper to get cached data by view/date
    const getCachedData = (view, date) => {
        if (view === 'clinical-director') {
            return date === 'today' ? cachedDirectorToday : null; // director is today-only
        }
        if (view === 'weekly-risk') {
            return cachedWeeklyRisk; // weekly-risk is not date-specific (covers current week)
        }
        return date === 'today' ? cachedDataToday : cachedDataYesterday;
    };

    // Send immediate data (either cached or trigger new query)
    const clientPrefs = allClients.get(ws);
    let cachedData = getCachedData(clientPrefs.view, clientPrefs.date);
    
    if (cachedData && (Date.now() - lastQueryTime) < 20000) {
        // Use cached data if it's less than 20 seconds old
        console.log(`Sending cached ${clientPrefs.date}/${clientPrefs.view} data to new client`);
        ws.send(JSON.stringify({ view: clientPrefs.view, data: cachedData }));
    } else {
        // Check if Snowflake is ready before triggering new query
        if (!snowflakeReady) {
            console.log(` Snowflake not ready, sending empty data to client. Will retry when connection is established.`);
            ws.send(JSON.stringify({ view: clientPrefs.view, data: [], message: 'Database connection not ready. Data will load shortly.' }));
        } else {
            // Trigger new query for the client's preferred date
            console.log(`No recent ${clientPrefs.date}/${clientPrefs.view} data, triggering new query for new client`);
            executeQueryForDate(clientPrefs.date, clientPrefs.view);
        }
    }
    
    ws.on('message', message => {
        console.log('Received WebSocket message:', message.toString());
        
        try {
            const parsedMessage = JSON.parse(message.toString());
            if (parsedMessage.view) {
                // Update this client's preferences
                const clientPrefs = allClients.get(ws);
                clientPrefs.view = parsedMessage.view;
                
                // Set date if provided (some views don't use dates)
                if (parsedMessage.date) {
                    clientPrefs.date = parsedMessage.date;
                }
                
                allClients.set(ws, clientPrefs);
                
                console.log(`Client updated: view=${parsedMessage.view}, date=${parsedMessage.date || 'N/A'}`);
                
                // Handle weekly-risk view separately (doesn't use date)
                if (parsedMessage.view === 'weekly-risk') {
                    if (cachedWeeklyRisk && (Date.now() - lastWeeklyRiskQueryTime) < 20000) {
                        ws.send(JSON.stringify({ view: 'weekly-risk', data: cachedWeeklyRisk }));
                    } else {
                        refreshWeeklyRiskData();
                    }
                } else {
                    // Send appropriate cached data immediately
                    const cachedDataNow = getCachedData(parsedMessage.view, parsedMessage.date || 'today');
                    if (cachedDataNow) {
                        ws.send(JSON.stringify({ view: parsedMessage.view, data: cachedDataNow }));
                    } else {
                        // If no cached data, trigger new query
                        executeQueryForDate(parsedMessage.date || 'today', parsedMessage.view);
                    }
                }
            } else {
                // Handle legacy string messages
                const clientPrefs = allClients.get(ws);
                clientPrefs.view = message.toString();
                allClients.set(ws, clientPrefs);
                console.log('Client view set to:', message.toString());
                
                // Send current cached data immediately
                const cachedDataLegacy = getCachedData(clientPrefs.view, clientPrefs.date);
                if (cachedDataLegacy) {
                    ws.send(JSON.stringify({ view: clientPrefs.view, data: cachedDataLegacy }));
                }
            }
        } catch (e) {
            // Handle legacy string messages
            const clientPrefs = allClients.get(ws);
            clientPrefs.view = message.toString();
            allClients.set(ws, clientPrefs);
            console.log('Client view set to:', message.toString());
            
            // Send current cached data immediately
            const cachedDataLegacy2 = getCachedData(clientPrefs.view, clientPrefs.date);
            if (cachedDataLegacy2) {
                ws.send(JSON.stringify({ view: clientPrefs.view, data: cachedDataLegacy2 }));
            }
        }
    });
    
    ws.on('close', () => {
        allClients.delete(ws);
        console.log(`WebSocket client disconnected. Total clients: ${allClients.size}`);
    });
});

// Add error handling for WebSocket server
wss.on('error', (error) => {
    console.error(' WebSocket server error:', error);
});

// Initial queries are now triggered in connectToSnowflake() callback
// (removed duplicate call to prevent race condition)

// Graceful shutdown handler
process.on('SIGINT', () => {
    console.log('Shutting down server...');
    // Clear background refresh interval
    if (clientCrossReportRefreshInterval) {
        clearInterval(clientCrossReportRefreshInterval);
    }
    logStream.end();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('Shutting down server...');
    // Clear background refresh interval
    if (clientCrossReportRefreshInterval) {
        clearInterval(clientCrossReportRefreshInterval);
    }
    logStream.end();
    process.exit(0);
});

// Start background refresh for client cross-report
// This will fetch data immediately and then refresh every 4 minutes
startClientCrossReportBackgroundRefresh();

// REMOVED: SQLite initialization for Zoom meetings - no longer needed