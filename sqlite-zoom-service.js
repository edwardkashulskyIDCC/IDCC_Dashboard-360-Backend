const Database = require('better-sqlite3');
const path = require('path');
const { zoomLog, zoomError } = require('./zoom-logger');

// Database file path - using the same database as scheduled emails
const DB_PATH = path.join(__dirname, 'scheduled-emails.db');

// Initialize database connection
let db = null;

/**
 * Initialize SQLite database and create table if it doesn't exist
 */
function initializeDatabase() {
    try {
        zoomLog('💾 Initializing SQLite database...');
        zoomLog('💾 Database path:', DB_PATH);
        
        if (!db) {
            // Try to connect with retries if database is locked
            let retries = 5;
            let connected = false;
            
            while (retries > 0 && !connected) {
                try {
                    // Configure database for concurrent access
                    db = new Database(DB_PATH, {
                        timeout: 30000 // Wait up to 30 seconds for locks
                    });
                    
                    // Enable WAL mode for better concurrent access (this might fail if DB is locked)
                    try {
                        db.pragma('journal_mode = WAL');
                    } catch (walError) {
                        zoomLog('⚠️ Could not set WAL mode (database may be locked):', walError.message);
                        // Continue anyway - WAL mode is optional
                    }
                    
                    // Set busy timeout to wait for locks (30 seconds)
                    try {
                        db.pragma('busy_timeout = 30000');
                    } catch (timeoutError) {
                        zoomLog('⚠️ Could not set busy timeout:', timeoutError.message);
                    }
                    
                    connected = true;
                    zoomLog('✅ Connected to SQLite database:', DB_PATH);
                    zoomLog('✅ WAL mode enabled for concurrent access');
                } catch (connectError) {
                    retries--;
                    if (connectError.message && connectError.message.includes('locked')) {
                        if (retries > 0) {
                            zoomLog(`⚠️ Database locked, retrying connection... (${retries} attempts remaining)`);
                            const sleep = (ms) => {
                                const start = Date.now();
                                while (Date.now() - start < ms) {}
                            };
                            sleep(1000); // Wait 1 second before retry
                        } else {
                            throw new Error('Database is locked and could not connect after retries. Another process may be using the database.');
                        }
                    } else {
                        throw connectError;
                    }
                }
            }
        }
        
        // Check if table already exists - if it does, skip ALL creation logic
        let tableExists = false;
        try {
            const checkTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='zoom_meetings'");
            const tableCheckResult = checkTable.get();
            tableExists = !!tableCheckResult;
        } catch (checkError) {
            // If we can't check, assume it doesn't exist and try to create
            zoomLog('⚠️ Could not check if table exists:', checkError.message);
            tableExists = false;
        }
        
        if (tableExists) {
            // Table exists - check if we need to add new columns (staff_name, client_name)
            try {
                const testQuery = db.prepare('SELECT COUNT(*) as count FROM zoom_meetings');
                const result = testQuery.get();
                zoomLog(`✅ zoom_meetings table exists (${result.count} records)`);
                
                // Check if staff_name column exists
                try {
                    db.prepare('SELECT staff_name FROM zoom_meetings LIMIT 1').get();
                    zoomLog('✅ staff_name column exists');
                } catch (e) {
                    zoomLog('⚠️ staff_name column does not exist, adding...');
                    try {
                        db.exec('ALTER TABLE zoom_meetings ADD COLUMN staff_name TEXT');
                        zoomLog('✅ Added staff_name column');
                    } catch (alterError) {
                        zoomError('❌ Failed to add staff_name column:', alterError.message);
                    }
                }
                
                // Check if client_name column exists
                try {
                    db.prepare('SELECT client_name FROM zoom_meetings LIMIT 1').get();
                    zoomLog('✅ client_name column exists');
                } catch (e) {
                    zoomLog('⚠️ client_name column does not exist, adding...');
                    try {
                        db.exec('ALTER TABLE zoom_meetings ADD COLUMN client_name TEXT');
                        zoomLog('✅ Added client_name column');
                    } catch (alterError) {
                        zoomError('❌ Failed to add client_name column:', alterError.message);
                    }
                }
                
                // Check if service_date column exists
                try {
                    db.prepare('SELECT service_date FROM zoom_meetings LIMIT 1').get();
                    zoomLog('✅ service_date column exists');
                } catch (e) {
                    zoomLog('⚠️ service_date column does not exist, adding...');
                    try {
                        db.exec('ALTER TABLE zoom_meetings ADD COLUMN service_date TEXT');
                        zoomLog('✅ Added service_date column');
                    } catch (alterError) {
                        zoomError('❌ Failed to add service_date column:', alterError.message);
                    }
                }
                
                // Check if time_from column exists
                try {
                    db.prepare('SELECT time_from FROM zoom_meetings LIMIT 1').get();
                    zoomLog('✅ time_from column exists');
                } catch (e) {
                    zoomLog('⚠️ time_from column does not exist, adding...');
                    try {
                        db.exec('ALTER TABLE zoom_meetings ADD COLUMN time_from TEXT');
                        zoomLog('✅ Added time_from column');
                    } catch (alterError) {
                        zoomError('❌ Failed to add time_from column:', alterError.message);
                    }
                }
                
                // Check if time_to column exists
                try {
                    db.prepare('SELECT time_to FROM zoom_meetings LIMIT 1').get();
                    zoomLog('✅ time_to column exists');
                } catch (e) {
                    zoomLog('⚠️ time_to column does not exist, adding...');
                    try {
                        db.exec('ALTER TABLE zoom_meetings ADD COLUMN time_to TEXT');
                        zoomLog('✅ Added time_to column');
                    } catch (alterError) {
                        zoomError('❌ Failed to add time_to column:', alterError.message);
                    }
                }
            } catch (verifyError) {
                zoomLog('⚠️ Table exists but cannot be queried:', verifyError.message);
            }
        } else {
            // Table doesn't exist - create it
            try {
                db.exec(`
                    CREATE TABLE IF NOT EXISTS zoom_meetings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        meeting_id INTEGER NOT NULL,
                        join_url TEXT NOT NULL,
                        start_url TEXT,
                        password TEXT,
                        topic TEXT,
                        duration INTEGER,
                        start_time TEXT,
                        timezone TEXT,
                        staff_id INTEGER,
                        client_id INTEGER,
                        staff_name TEXT,
                        client_name TEXT,
                        service_date TEXT,
                        time_from TEXT,
                        time_to TEXT,
                        service_id INTEGER,
                        organization_id INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                `);
                
                // Create indexes separately
                db.exec(`
                    CREATE INDEX IF NOT EXISTS idx_meeting_id ON zoom_meetings(meeting_id);
                    CREATE INDEX IF NOT EXISTS idx_staff_id ON zoom_meetings(staff_id);
                    CREATE INDEX IF NOT EXISTS idx_client_id ON zoom_meetings(client_id);
                    CREATE INDEX IF NOT EXISTS idx_service_id ON zoom_meetings(service_id);
                    CREATE INDEX IF NOT EXISTS idx_created_at ON zoom_meetings(created_at);
                `);
                zoomLog('✅ zoom_meetings table created');
            } catch (tableError) {
                if (tableError.message && tableError.message.includes('locked')) {
                    zoomLog('⚠️ Database locked - table creation skipped. Table may already exist.');
                } else {
                    zoomLog('⚠️ Could not create table:', tableError.message);
                }
            }
        }
        
        return true;
    } catch (error) {
        zoomError('❌ Error initializing SQLite database:', error);
        zoomError('❌ Error message:', error.message);
        zoomError('❌ Error stack:', error.stack);
        return false;
    }
}

/**
 * Get database connection (initialize if needed)
 */
function getDatabase() {
    if (!db) {
        zoomLog('💾 Database not initialized, calling initializeDatabase()...');
        const success = initializeDatabase();
        if (!success) {
            throw new Error('Failed to initialize database');
        }
    }
    
    // Verify connection is still valid
    if (!db.open) {
        zoomLog('⚠️ Database connection is closed, reinitializing...');
        db = null;
        const success = initializeDatabase();
        if (!success) {
            throw new Error('Failed to reinitialize database');
        }
    }
    
    // Ensure WAL mode is enabled (in case connection was reset)
    try {
        const journalMode = db.pragma('journal_mode', { simple: true });
        const busyTimeout = db.pragma('busy_timeout', { simple: true });
        zoomLog(`💾 Database pragmas: journal_mode=${journalMode}, busy_timeout=${busyTimeout}`);
        
        if (journalMode !== 'wal') {
            db.pragma('journal_mode = WAL');
            zoomLog('✅ Set journal_mode to WAL');
        }
        if (busyTimeout < 30000) {
            db.pragma('busy_timeout = 30000');
            zoomLog('✅ Set busy_timeout to 30000');
        }
    } catch (pragmaError) {
        zoomLog('⚠️ Could not set database pragmas:', pragmaError.message);
    }
    
    // Verify we're using the correct database file
    try {
        const dbPath = db.prepare("PRAGMA database_list").all().find(d => d.name === 'main')?.file;
        zoomLog('💾 Current database file:', dbPath || DB_PATH);
        if (dbPath && !dbPath.includes('scheduled-emails.db')) {
            zoomLog('⚠️ WARNING: Database file does not match expected path!');
        }
    } catch (pathError) {
        zoomLog('⚠️ Could not verify database path:', pathError.message);
    }
    
    return db;
}

/**
 * Save Zoom meeting to SQLite database
 * @param {Object} meetingData - Meeting data from Zoom API
 * @param {Object} contextData - Context data (staffId, clientId, etc.)
 * @returns {Object} Saved meeting record
 */
function saveZoomMeeting(meetingData, contextData = {}) {
    try {
        zoomLog('💾 saveZoomMeeting called with:');
        zoomLog('   Meeting data:', JSON.stringify(meetingData, null, 2));
        zoomLog('   Context data:', JSON.stringify(contextData, null, 2));
        
        const database = getDatabase();
        
        if (!database) {
            throw new Error('Database not initialized');
        }
        
        // Verify we're using the correct database and list all tables for debugging
        try {
            const allTables = database.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
            zoomLog('📋 All tables in database:', allTables.map(t => t.name).join(', '));
            zoomLog('📋 Database file:', DB_PATH);
            zoomLog('📋 Database connection state:', {
                open: database.open,
                readonly: database.readonly,
                inTransaction: database.inTransaction
            });
        } catch (debugError) {
            zoomLog('⚠️ Could not list tables:', debugError.message);
        }
        
        // Force schema refresh by querying sqlite_master
        try {
            const schemaCheck = database.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='zoom_meetings'").get();
            if (schemaCheck) {
                zoomLog('✅ zoom_meetings table found in schema');
            } else {
                zoomLog('⚠️ zoom_meetings table NOT found in schema');
            }
        } catch (schemaError) {
            zoomLog('⚠️ Error checking schema:', schemaError.message);
        }
        
        // Try to query the table directly - if it fails, we know it doesn't exist
        let tableExists = false;
        let tableCheckAttempts = 3;
        
        while (tableCheckAttempts > 0) {
            try {
                // Use exec instead of prepare to avoid caching issues
                const testResult = database.prepare('SELECT COUNT(*) as count FROM zoom_meetings').get();
                tableExists = true;
                zoomLog(`✅ zoom_meetings table exists and is accessible (${testResult.count} records)`);
                break;
            } catch (testError) {
                tableCheckAttempts--;
                if (testError.message && testError.message.includes('no such table')) {
                    zoomLog(`⚠️ zoom_meetings table does not exist (attempt ${4 - tableCheckAttempts}/3)`);
                    if (tableCheckAttempts === 0) {
                        tableExists = false;
                    } else {
                        // Wait a bit and retry - might be a WAL sync issue
                        const sleep = (ms) => {
                            const start = Date.now();
                            while (Date.now() - start < ms) {}
                        };
                        sleep(200);
                    }
                } else {
                    // Might be a lock error, retry
                    zoomLog('⚠️ Error checking table (may be locked):', testError.message);
                    if (tableCheckAttempts === 0) {
                        throw testError;
                    } else {
                        const sleep = (ms) => {
                            const start = Date.now();
                            while (Date.now() - start < ms) {}
                        };
                        sleep(200);
                    }
                }
            }
        }
        
        // Create table if it doesn't exist (with retry for locks)
        if (!tableExists) {
            zoomLog('⚠️ Table does not exist or is not accessible, attempting to create...');
            let createRetries = 5;
            let tableCreated = false;
            
            while (createRetries > 0 && !tableCreated) {
                try {
                    database.exec(`
                        CREATE TABLE IF NOT EXISTS zoom_meetings (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            meeting_id INTEGER NOT NULL,
                            join_url TEXT NOT NULL,
                            start_url TEXT,
                            password TEXT,
                            topic TEXT,
                            duration INTEGER,
                            start_time TEXT,
                            timezone TEXT,
                            staff_id INTEGER,
                            client_id INTEGER,
                            staff_name TEXT,
                            client_name TEXT,
                            service_date TEXT,
                            time_from TEXT,
                            time_to TEXT,
                            service_id INTEGER,
                            organization_id INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        );
                    `);
                    tableCreated = true;
                    zoomLog('✅ Created zoom_meetings table');
                    
                    // Verify it was created
                    const verifyResult = database.prepare('SELECT COUNT(*) as count FROM zoom_meetings').get();
                    zoomLog(`✅ Verified table exists after creation (${verifyResult.count} records)`);
                } catch (createError) {
                    createRetries--;
                    const isLocked = createError.message && (
                        createError.message.includes('locked') || 
                        createError.message.includes('SQLITE_BUSY') ||
                        createError.code === 'SQLITE_BUSY'
                    );
                    if (isLocked && createRetries > 0) {
                        zoomLog(`⚠️ Database locked while creating table, retrying... (${createRetries} attempts remaining)`);
                        const sleep = (ms) => {
                            const start = Date.now();
                            while (Date.now() - start < ms) {}
                        };
                        sleep(500);
                    } else {
                        throw new Error(`Could not create table: ${createError.message}`);
                    }
                }
            }
        }
        
        // Final verification before insert
        try {
            const finalCheck = database.prepare('SELECT COUNT(*) as count FROM zoom_meetings').get();
            zoomLog(`✅ Final verification: zoom_meetings table is accessible (${finalCheck.count} records)`);
        } catch (finalError) {
            zoomError('❌ CRITICAL: Table is not accessible right before insert:', finalError.message);
            throw new Error(`Table zoom_meetings is not accessible: ${finalError.message}`);
        }
        
        // Validate required fields
        if (!meetingData || !meetingData.meeting_id || !meetingData.join_url) {
            throw new Error('Missing required fields: meeting_id and join_url are required');
        }
        
        const {
            meeting_id,
            join_url,
            start_url,
            password,
            topic,
            duration,
            start_time,
            timezone
        } = meetingData;
        
        const {
            staffId,
            clientId,
            staffName,
            clientName,
            serviceDate,
            timeFrom,
            timeTo,
            serviceId,
            organizationId
        } = contextData;
        
        zoomLog('💾 Preparing to insert Zoom meeting:');
        zoomLog('   meeting_id:', meeting_id, '(type:', typeof meeting_id, ')');
        zoomLog('   join_url:', join_url);
        zoomLog('   staffId:', staffId, '(type:', typeof staffId, ')');
        zoomLog('   clientId:', clientId, '(type:', typeof clientId, ')');
        zoomLog('   serviceId:', serviceId, '(type:', typeof serviceId, ')');
        zoomLog('   organizationId:', organizationId, '(type:', typeof organizationId, ')');
        
        const insertQuery = `
            INSERT INTO zoom_meetings (
                meeting_id,
                join_url,
                start_url,
                password,
                topic,
                duration,
                start_time,
                timezone,
                staff_id,
                client_id,
                staff_name,
                client_name,
                service_date,
                time_from,
                time_to,
                service_id,
                organization_id,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        zoomLog('💾 Executing insert query...');
        
        // Retry logic for database locks - more aggressive retries
        let retries = 10; // Increased retries
        let result = null;
        let lastError = null;
        
        while (retries > 0) {
            try {
                // Prepare statement fresh each time
                const stmt = database.prepare(insertQuery);
                // Ensure IDs are integers or null (handle objects, strings, numbers)
                const parseIdForInsert = (id) => {
                    if (id === null || id === undefined || id === '') return null;
                    // Handle empty objects
                    if (typeof id === 'object' && Object.keys(id).length === 0) return null;
                    // If it's an object with an 'id' property, use that
                    if (typeof id === 'object' && id !== null && id.id !== undefined) {
                        const parsed = parseInt(id.id);
                        return isNaN(parsed) ? null : parsed;
                    }
                    // Handle string or number
                    const parsed = parseInt(id);
                    return isNaN(parsed) ? null : parsed;
                };
                
                const finalStaffId = parseIdForInsert(staffId);
                const finalClientId = parseIdForInsert(clientId);
                const finalServiceId = parseIdForInsert(serviceId);
                const finalOrganizationId = parseIdForInsert(organizationId);
                
                zoomLog('💾 Final values for insert:');
                zoomLog('   staffId:', finalStaffId, '(type:', typeof finalStaffId, ')');
                zoomLog('   clientId:', finalClientId, '(type:', typeof finalClientId, ')');
                zoomLog('   staffName:', staffName || null, '(type:', typeof staffName, ')');
                zoomLog('   clientName:', clientName || null, '(type:', typeof clientName, ')');
                zoomLog('   serviceDate:', serviceDate || null, '(type:', typeof serviceDate, ')');
                zoomLog('   timeFrom:', timeFrom || null, '(type:', typeof timeFrom, ')');
                zoomLog('   timeTo:', timeTo || null, '(type:', typeof timeTo, ')');
                zoomLog('   serviceId:', finalServiceId, '(type:', typeof finalServiceId, ')');
                zoomLog('   organizationId:', finalOrganizationId, '(type:', typeof finalOrganizationId, ')');
                
                result = stmt.run(
                    meeting_id,
                    join_url,
                    start_url || null,
                    password || null,
                    topic || null,
                    duration || null,
                    start_time || null,
                    timezone || null,
                    finalStaffId,
                    finalClientId,
                    staffName || null,
                    clientName || null,
                    serviceDate || null,
                    timeFrom || null,
                    timeTo || null,
                    finalServiceId,
                    finalOrganizationId
                );
                // Success - break out of retry loop
                zoomLog('✅ Insert succeeded on attempt', (11 - retries));
                break;
            } catch (insertError) {
                lastError = insertError;
                const isLocked = insertError.message && (
                    insertError.message.includes('locked') || 
                    insertError.message.includes('SQLITE_BUSY') ||
                    insertError.code === 'SQLITE_BUSY'
                );
                
                if (isLocked) {
                    retries--;
                    if (retries > 0) {
                        const waitTime = 500 * (11 - retries); // Exponential backoff: 500ms, 1000ms, 1500ms, etc.
                        zoomLog(`⚠️ Database locked during insert, waiting ${waitTime}ms and retrying... (${retries} attempts remaining)`);
                        // Use setTimeout for async wait (but we're in sync function, so use busy wait)
                        const sleep = (ms) => {
                            const start = Date.now();
                            while (Date.now() - start < ms) {}
                        };
                        sleep(waitTime);
                    } else {
                        zoomError('❌ Database locked - all retry attempts exhausted');
                        throw new Error(`Database is locked and could not save after 10 attempts. Another process (email scheduler?) is using the database. Error: ${insertError.message}`);
                    }
                } else {
                    // Not a locking error, throw immediately
                    zoomError('❌ Insert error (not a lock):', insertError.message);
                    throw insertError;
                }
            }
        }
        
        if (!result) {
            throw lastError || new Error('Insert failed after retries');
        }
        
        zoomLog(`✅ Insert result:`, {
            lastInsertRowid: result.lastInsertRowid,
            changes: result.changes
        });
        
        if (!result.lastInsertRowid) {
            throw new Error('Insert failed - no row ID returned');
        }
        
        // Checkpoint WAL to ensure changes are immediately visible in DB Browser
        try {
            // Use exec for pragma with parameters - TRUNCATE ensures WAL is fully checkpointed
            database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
            zoomLog('✅ WAL checkpoint completed - changes are now visible in DB Browser');
        } catch (checkpointError) {
            // If checkpoint fails, it's not critical - changes are still in WAL
            zoomLog('⚠️ WAL checkpoint warning (non-critical):', checkpointError.message);
        }
        
        // Return the saved record
        const savedRecord = database.prepare('SELECT * FROM zoom_meetings WHERE id = ?').get(result.lastInsertRowid);
        
        if (!savedRecord) {
            throw new Error('Failed to retrieve saved record');
        }
        
        zoomLog(`✅ Saved Zoom meeting to SQLite: ID=${savedRecord.id}, Meeting ID=${savedRecord.meeting_id}`);
        zoomLog('   Full saved record:', JSON.stringify(savedRecord, null, 2));
        
        return {
            id: savedRecord.id,
            meeting_id: savedRecord.meeting_id,
            join_url: savedRecord.join_url,
            start_url: savedRecord.start_url,
            password: savedRecord.password,
            topic: savedRecord.topic,
            duration: savedRecord.duration,
            start_time: savedRecord.start_time,
            timezone: savedRecord.timezone,
            staff_id: savedRecord.staff_id,
            client_id: savedRecord.client_id,
            service_id: savedRecord.service_id,
            organization_id: savedRecord.organization_id,
            created_at: savedRecord.created_at,
            updated_at: savedRecord.updated_at
        };
    } catch (error) {
        zoomError('❌ Error saving Zoom meeting to SQLite:', error);
        zoomError('   Error message:', error.message);
        zoomError('   Error stack:', error.stack);
        throw error;
    }
}

/**
 * Get Zoom meetings by filters
 * @param {Object} filters - Filter criteria
 * @returns {Array} Array of meeting records
 */
function getZoomMeetings(filters = {}) {
    try {
        const database = getDatabase();
        
        let query = 'SELECT * FROM zoom_meetings WHERE 1=1';
        const params = [];
        
        if (filters.meeting_id) {
            query += ' AND meeting_id = ?';
            params.push(filters.meeting_id);
        }
        
        if (filters.staff_id) {
            query += ' AND staff_id = ?';
            params.push(filters.staff_id);
        }
        
        if (filters.client_id) {
            query += ' AND client_id = ?';
            params.push(filters.client_id);
        }
        
        if (filters.start_date) {
            query += ' AND created_at >= ?';
            params.push(filters.start_date);
        }
        
        if (filters.end_date) {
            query += ' AND created_at <= ?';
            params.push(filters.end_date);
        }
        
        query += ' ORDER BY created_at DESC';
        
        if (filters.limit) {
            query += ' LIMIT ?';
            params.push(filters.limit);
        }
        
        const stmt = database.prepare(query);
        const rows = stmt.all(...params);
        
        return rows;
    } catch (error) {
        zoomError('❌ Error fetching Zoom meetings from SQLite:', error);
        throw error;
    }
}

module.exports = {
    initializeDatabase,
    saveZoomMeeting,
    getZoomMeetings,
    getDatabase
};

