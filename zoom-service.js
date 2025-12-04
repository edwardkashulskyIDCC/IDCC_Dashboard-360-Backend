const https = require('https');
const { Buffer } = require('buffer');
const { zoomLog, zoomError } = require('./zoom-logger');

// Zoom API Configuration
const ZOOM_CONFIG = {
    accountId: '5jxQLAmYSBi00dd2-4bSyw',
    clientId: 'uXnCnTueREKY16vH373XpA',
    clientSecret: 'rOxvAuOfILVYwxKPzk3SxYYx07XBg7ZZ',
    tokenUrl: 'https://zoom.us/oauth/token',
    apiBaseUrl: 'https://api.zoom.us/v2'
};

// Cache for access token (with expiry)
let accessTokenCache = {
    token: null,
    expiresAt: null
};

/**
 * Get Zoom OAuth access token using Server-to-Server OAuth
 * @returns {Promise<string>} Access token
 */
async function getAccessToken() {
    // Return cached token if still valid (with 5 minute buffer)
    if (accessTokenCache.token && accessTokenCache.expiresAt && Date.now() < (accessTokenCache.expiresAt - 300000)) {
        zoomLog('Using cached Zoom access token');
        return accessTokenCache.token;
    }

    return new Promise((resolve, reject) => {
        const authString = Buffer.from(`${ZOOM_CONFIG.clientId}:${ZOOM_CONFIG.clientSecret}`).toString('base64');
        
        // Zoom OAuth requires form-encoded data, not JSON
        const querystring = require('querystring');
        const postData = querystring.stringify({
            grant_type: 'account_credentials',
            account_id: ZOOM_CONFIG.accountId
        });

        const options = {
            hostname: 'zoom.us',
            path: '/oauth/token',
            method: 'POST',
            headers: {
                'Authorization': `Basic ${authString}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const response = JSON.parse(data);
                        const accessToken = response.access_token;
                        const expiresIn = response.expires_in || 3600; // Default to 1 hour
                        
                        // Cache the token
                        accessTokenCache.token = accessToken;
                        accessTokenCache.expiresAt = Date.now() + (expiresIn * 1000);
                        
                        zoomLog('Successfully obtained Zoom access token');
                        resolve(accessToken);
                    } else {
                        zoomError('Zoom token error response:', res.statusCode, data);
                        reject(new Error(`Failed to get access token: ${res.statusCode} - ${data}`));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom token response:', error);
                    reject(new Error(`Failed to parse token response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom token request error:', error);
            reject(new Error(`Network error getting token: ${error.message}`));
        });

        req.write(postData);
        req.end();
    });
}

/**
 * Create a Zoom meeting
 * @param {Object} meetingOptions - Meeting options
 * @param {string} meetingOptions.topic - Meeting topic/title
 * @param {number} meetingOptions.duration - Duration in minutes (default: 30)
 * @param {string} meetingOptions.start_time - Start time in ISO 8601 format (optional)
 * @param {string} meetingOptions.description - Meeting description/agenda (optional)
 * @param {Object} meetingOptions.settings - Additional settings (optional)
 * @param {string} meetingOptions.hostEmail - Email of the user to create meeting for (optional, defaults to "me")
 * @returns {Promise<Object>} Meeting details including join_url
 */
async function createMeeting(meetingOptions = {}) {
    const accessToken = await getAccessToken();

    const {
        topic = 'Carelogic Meeting',
        duration = 30,
        start_time = null,
        description = null,
        settings = {},
        hostEmail = null // If provided, create meeting on behalf of this user
    } = meetingOptions;

    // Add unique identifier to topic to force Zoom to create a new meeting
    // This prevents Zoom from reusing the same meeting ID
    const uniqueId = Date.now().toString(36) + Math.random().toString(36).substring(2, 9);
    const uniqueTopic = `${topic} [${uniqueId}]`;
    
    zoomLog('🔑 Creating meeting with unique identifier:', uniqueId);
    zoomLog('📝 Original topic:', topic);
    zoomLog('📝 Unique topic:', uniqueTopic);

    const meetingData = {
        topic: uniqueTopic, // Use unique topic to force new meeting creation
        type: 2, // Scheduled meeting (1=instant, 2=scheduled, 3=recurring no fixed time, 8=recurring fixed time)
        duration: duration,
        settings: {
            host_video: true,
            participant_video: true,
            join_before_host: false,
            mute_upon_entry: false,
            waiting_room: true,
            audio: 'both', // 'both', 'telephony', 'voip'
            auto_recording: 'none', // 'none', 'local', 'cloud'
            use_pmi: false, // IMPORTANT: Disable Personal Meeting Room reuse to ensure unique meetings
            // Additional settings to prevent meeting reuse
            approval_type: 0, // Automatically approve all participants
            registration_type: 0, // No registration required
            ...settings
        }
    };

    // Add start_time if provided
    if (start_time) {
        meetingData.start_time = start_time;
        // Use America/New_York as default timezone
        // Note: The frontend sends local time, so we assume it's in this timezone
        // If you need to support multiple timezones, you can pass timezone in meetingOptions
        meetingData.timezone = meetingOptions.timezone || 'America/New_York';
    } else {
        // If no start_time, create instant meeting (type 1)
        meetingData.type = 1;
    }
    
    // Add description/agenda if provided (max 2000 characters for Zoom)
    if (description && description.trim()) {
        meetingData.agenda = description.substring(0, 2000);
    }

    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(meetingData);

        // If hostEmail is provided, create meeting on behalf of that user
        // Otherwise, create for "me" (the OAuth app account)
        const userPath = hostEmail ? `/v2/users/${hostEmail}/meetings` : '/v2/users/me/meetings';
        
        if (hostEmail) {
            zoomLog(`📧 Creating meeting on behalf of user: ${hostEmail}`);
        } else {
            zoomLog('📧 Creating meeting for OAuth app account (me)');
        }

        const options = {
            hostname: 'api.zoom.us',
            path: userPath,
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 201) {
                        const response = JSON.parse(data);
                        zoomLog('✅ Successfully created Zoom meeting:', response.id);
                        zoomLog('📋 Meeting details:', {
                            id: response.id,
                            topic: response.topic,
                            join_url: response.join_url,
                            start_time: response.start_time,
                            duration: response.duration
                        });
                        
                        // IMPORTANT: Verify this is a new meeting by checking the response
                        // Extract the original topic (remove unique ID suffix)
                        const originalTopic = response.topic.replace(/\s*\[[a-z0-9]+\]$/i, '');
                        
                        resolve({
                            success: true,
                            meeting_id: response.id,
                            join_url: response.join_url,
                            start_url: response.start_url,
                            password: response.password,
                            topic: originalTopic, // Return original topic without unique ID
                            duration: response.duration,
                            start_time: response.start_time
                        });
                    } else {
                        zoomError('Zoom meeting creation error:', res.statusCode, data);
                        let errorMessage = `Failed to create meeting: ${res.statusCode}`;
                        try {
                            const errorData = JSON.parse(data);
                            errorMessage = `${errorMessage} - ${errorData.message || errorData.code || JSON.stringify(errorData)}`;
                        } catch (parseError) {
                            // If response is not JSON, use the raw data
                            errorMessage = `${errorMessage} - ${data}`;
                        }
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom meeting response:', error);
                    reject(new Error(`Failed to parse meeting response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom meeting request error:', error);
            reject(new Error(`Network error creating meeting: ${error.message}`));
        });

        req.write(postData);
        req.end();
    });
}

/**
 * Get meeting details by meeting ID
 * @param {number} meetingId - Zoom meeting ID
 * @returns {Promise<Object>} Meeting details
 */
async function getMeeting(meetingId) {
    const accessToken = await getAccessToken();

    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.zoom.us',
            path: `/v2/meetings/${meetingId}`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const response = JSON.parse(data);
                        zoomLog('✅ Retrieved meeting details:', meetingId);
                        resolve({
                            success: true,
                            meeting: response
                        });
                    } else {
                        zoomError('Zoom get meeting error:', res.statusCode, data);
                        let errorMessage = `Failed to get meeting: ${res.statusCode}`;
                        try {
                            const errorData = JSON.parse(data);
                            errorMessage = `${errorMessage} - ${errorData.message || errorData.code || JSON.stringify(errorData)}`;
                        } catch (parseError) {
                            errorMessage = `${errorMessage} - ${data}`;
                        }
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom meeting response:', error);
                    reject(new Error(`Failed to parse meeting response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom meeting request error:', error);
            reject(new Error(`Network error getting meeting: ${error.message}`));
        });

        req.end();
    });
}

/**
 * Get live meeting metrics (requires Dashboard API access - Business+ plan)
 * This can help determine if a meeting is currently in progress
 * @param {number} meetingId - Zoom meeting ID
 * @returns {Promise<Object>} Meeting metrics including participant count
 */
async function getMeetingMetrics(meetingId) {
    const accessToken = await getAccessToken();

    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.zoom.us',
            path: `/v2/metrics/meetings/${meetingId}`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const response = JSON.parse(data);
                        zoomLog('✅ Retrieved meeting metrics:', meetingId);
                        resolve({
                            success: true,
                            metrics: response,
                            isLive: response.participants && response.participants.length > 0
                        });
                    } else if (res.statusCode === 404) {
                        // Meeting not found or not currently live
                        resolve({
                            success: false,
                            isLive: false,
                            error: 'Meeting not found or not currently in progress'
                        });
                    } else {
                        zoomError('Zoom metrics error:', res.statusCode, data);
                        let errorMessage = `Failed to get meeting metrics: ${res.statusCode}`;
                        try {
                            const errorData = JSON.parse(data);
                            errorMessage = `${errorMessage} - ${errorData.message || errorData.code || JSON.stringify(errorData)}`;
                        } catch (parseError) {
                            errorMessage = `${errorMessage} - ${data}`;
                        }
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom metrics response:', error);
                    reject(new Error(`Failed to parse metrics response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom metrics request error:', error);
            reject(new Error(`Network error getting metrics: ${error.message}`));
        });

        req.end();
    });
}

/**
 * Get meeting participants (for past meetings)
 * @param {number} meetingId - Zoom meeting ID
 * @param {string} meetingType - 'past' or 'live' (default: 'past')
 * @returns {Promise<Object>} Participant list
 */
async function getMeetingParticipants(meetingId, meetingType = 'past') {
    const accessToken = await getAccessToken();

    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.zoom.us',
            path: `/v2/report/meetings/${meetingId}/participants`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const response = JSON.parse(data);
                        zoomLog('✅ Retrieved meeting participants:', meetingId);
                        resolve({
                            success: true,
                            participants: response.participants || [],
                            total_records: response.total_records || 0
                        });
                    } else {
                        zoomError('Zoom participants error:', res.statusCode, data);
                        let errorMessage = `Failed to get participants: ${res.statusCode}`;
                        try {
                            const errorData = JSON.parse(data);
                            errorMessage = `${errorMessage} - ${errorData.message || errorData.code || JSON.stringify(errorData)}`;
                        } catch (parseError) {
                            errorMessage = `${errorMessage} - ${data}`;
                        }
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom participants response:', error);
                    reject(new Error(`Failed to parse participants response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom participants request error:', error);
            reject(new Error(`Network error getting participants: ${error.message}`));
        });

        req.end();
    });
}

/**
 * Update a Zoom meeting (e.g., to add host link to agenda)
 * @param {number} meetingId - Zoom meeting ID
 * @param {string} hostEmail - Email of the meeting host
 * @param {Object} updateData - Data to update (agenda, topic, etc.)
 * @returns {Promise<Object>} Updated meeting details
 */
async function updateMeeting(meetingId, hostEmail, updateData) {
    const accessToken = await getAccessToken();

    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(updateData);
        const userPath = hostEmail ? `/v2/users/${hostEmail}/meetings/${meetingId}` : `/v2/meetings/${meetingId}`;

        const options = {
            hostname: 'api.zoom.us',
            path: userPath,
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 204 || res.statusCode === 200) {
                        // 204 No Content means success for PATCH
                        zoomLog('✅ Successfully updated Zoom meeting:', meetingId);
                        resolve({
                            success: true,
                            meeting_id: meetingId
                        });
                    } else {
                        zoomError('Zoom meeting update error:', res.statusCode, data);
                        let errorMessage = `Failed to update meeting: ${res.statusCode}`;
                        try {
                            const errorData = JSON.parse(data);
                            errorMessage = `${errorMessage} - ${errorData.message || errorData.code || JSON.stringify(errorData)}`;
                        } catch (parseError) {
                            errorMessage = `${errorMessage} - ${data}`;
                        }
                        reject(new Error(errorMessage));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom meeting update response:', error);
                    reject(new Error(`Failed to parse update response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom meeting update request error:', error);
            reject(new Error(`Network error updating meeting: ${error.message}`));
        });

        req.write(postData);
        req.end();
    });
}

/**
 * Determine meeting status based on available information
 * @param {number} meetingId - Zoom meeting ID
 * @returns {Promise<Object>} Meeting status information
 */
async function getMeetingStatus(meetingId) {
    try {
        // First, get basic meeting details
        const meetingDetails = await getMeeting(meetingId);
        const meeting = meetingDetails.meeting;
        
        // Use Zoom's status field if available (more accurate)
        // Zoom status values: "waiting", "started", "finished"
        let status = 'unknown';
        let isLive = false;
        
        // Check Zoom's native status field first
        // NOTE: Zoom status changes to "started" only when someone actually joins,
        // not just when the host clicks "Start" (if host is alone, status stays "waiting")
        if (meeting.status) {
            const zoomStatus = meeting.status.toLowerCase();
            const now = new Date();
            const startTime = meeting.start_time ? new Date(meeting.start_time) : null;
            const duration = meeting.duration || 30;
            const endTime = startTime ? new Date(startTime.getTime() + duration * 60000) : null;
            
            if (zoomStatus === 'waiting') {
                // Check if meeting time has passed
                if (startTime && now >= startTime) {
                    // Meeting time has passed but status is still "waiting"
                    // Check if end time has also passed - if so, meeting has ended
                    if (endTime && now > endTime) {
                        status = 'ended';
                        isLive = false;
                        zoomLog(`📊 Zoom status is "waiting" but end time has passed - marking as ended`);
                    } else {
                        // Meeting time has passed but hasn't ended yet - might be in progress
                        // We'll check participants below to confirm
                        status = 'scheduled'; // Keep as scheduled for now, will check participants
                        zoomLog(`📊 Zoom status is "waiting" but meeting time has passed - will check participants`);
                    }
                } else {
                    // Scheduled time is in the future, but check participants anyway
                    // Meeting might have happened earlier than scheduled
                    status = 'scheduled'; // Default, but will be overridden by participant check if meeting happened
                    zoomLog(`📊 Zoom status is "waiting" and scheduled time is in future - will check participants for actual meeting time`);
                }
            } else if (zoomStatus === 'started') {
                status = 'in_progress';
                isLive = true;
            } else if (zoomStatus === 'finished') {
                status = 'ended';
            } else {
                // Use the status as-is if it's something else
                status = zoomStatus;
            }
            zoomLog(`📊 Using Zoom API status: "${meeting.status}" -> "${status}"`);
        }
        
        // Fallback to time-based calculation if Zoom status not available
        if (status === 'unknown') {
            const now = new Date();
            const startTime = meeting.start_time ? new Date(meeting.start_time) : null;
            const duration = meeting.duration || 30; // minutes
            const endTime = startTime ? new Date(startTime.getTime() + duration * 60000) : null;
            
            // Determine status based on time
            if (startTime) {
                if (now < startTime) {
                    status = 'scheduled';
                } else if (endTime && now > endTime) {
                    status = 'ended';
                } else if (now >= startTime && (!endTime || now <= endTime)) {
                    status = 'in_progress';
                    isLive = true;
                }
            } else {
                // Instant meeting - could be live or ended
                status = 'instant';
            }
            zoomLog(`📊 Calculated status from time: "${status}"`);
        }
        
        // Check for participants - if there are participants, meeting has started
        // Zoom status might still say "waiting" if host started but no one joined yet
        // But if participants exist, the meeting is definitely in progress
        // CRITICAL: Use actual participant join/leave times to determine if meeting has ended,
        // regardless of scheduled time (meeting might have happened earlier than scheduled)
        try {
            const participants = await getMeetingParticipants(meetingId);
            if (participants.success && participants.participants && participants.participants.length > 0) {
                const now = new Date();
                
                // Find the earliest join time and latest leave time from all participants
                let earliestJoin = null;
                let latestLeave = null;
                
                participants.participants.forEach(p => {
                    if (p.join_time) {
                        const joinTime = new Date(p.join_time);
                        if (!earliestJoin || joinTime < earliestJoin) {
                            earliestJoin = joinTime;
                        }
                    }
                    if (p.leave_time) {
                        const leaveTime = new Date(p.leave_time);
                        if (!latestLeave || leaveTime > latestLeave) {
                            latestLeave = leaveTime;
                        }
                    }
                });
                
                zoomLog(`📊 Participant times - Earliest join: ${earliestJoin ? earliestJoin.toISOString() : 'N/A'}, Latest leave: ${latestLeave ? latestLeave.toISOString() : 'N/A'}`);
                
                // Check if any participants are currently in the meeting (not just historical)
                const activeParticipants = participants.participants.filter(p => {
                    // If participant has join_time but no leave_time, or leave_time is in the future, they're active
                    if (p.join_time) {
                        const joinTime = new Date(p.join_time);
                        if (!p.leave_time) {
                            return true; // No leave time = still in meeting
                        }
                        const leaveTime = new Date(p.leave_time);
                        if (now >= joinTime && now <= leaveTime) {
                            return true; // Currently in the meeting window
                        }
                    }
                    return false;
                });
                
                if (activeParticipants.length > 0) {
                    status = 'in_progress';
                    isLive = true;
                    zoomLog(`📊 Found ${activeParticipants.length} active participant(s) - meeting is in progress`);
                } else if (participants.participants.length > 0) {
                    // Has participants but none are currently active
                    // IMPORTANT: If Zoom API says "started", trust that over participant leave times
                    // The meeting room might still be open even if participants have left
                    const zoomStatus = meeting.status ? meeting.status.toLowerCase() : '';
                    if (zoomStatus === 'started') {
                        // Zoom says meeting is started - keep it as in_progress
                        status = 'in_progress';
                        isLive = true;
                        zoomLog(`📊 Zoom API says "started" - keeping status as in_progress (participants may have left but meeting room is still open)`);
                    } else if (latestLeave && now > latestLeave) {
                        // All participants have left and current time is after the last leave time
                        // Only mark as ended if Zoom doesn't say "started"
                        status = 'ended';
                        isLive = false;
                        zoomLog(`📊 Meeting has ended based on participant leave times (last leave: ${latestLeave.toISOString()})`);
                    } else if (earliestJoin && !latestLeave) {
                        // Some participants joined but haven't left yet - might still be in progress
                        // But if join was more than 2 hours ago and no one is active, likely ended
                        const hoursSinceJoin = (now.getTime() - earliestJoin.getTime()) / (1000 * 60 * 60);
                        if (hoursSinceJoin > 2) {
                            status = 'ended';
                            isLive = false;
                            zoomLog(`📊 Meeting likely ended - participants joined ${hoursSinceJoin.toFixed(1)} hours ago but none are active`);
                        } else {
                            zoomLog(`📊 Meeting has participants but none currently active (joined ${hoursSinceJoin.toFixed(1)} hours ago)`);
                        }
                    } else {
                        // Fallback: Check if scheduled end time has passed
                        const startTime = meeting.start_time ? new Date(meeting.start_time) : null;
                        const duration = meeting.duration || 30;
                        const endTime = startTime ? new Date(startTime.getTime() + duration * 60000) : null;
                        
                        if (endTime && now > endTime) {
                            status = 'ended';
                            isLive = false;
                            zoomLog('📊 Meeting has participants but scheduled end time has passed - status: ended');
                        } else {
                            // Meeting has participants but they've left - might be between sessions
                            // Keep current status but log it
                            zoomLog(`📊 Meeting has ${participants.participants.length} participant(s) but none currently active`);
                        }
                    }
                }
            }
        } catch (participantsError) {
            // Participants API might fail for various reasons
            zoomLog('⚠️ Could not get meeting participants:', participantsError.message);
        }
        
        // Try to get live metrics to confirm if meeting is actually happening
        // This can override the status if metrics are available
        // IMPORTANT: If Zoom API says "started", trust that over metrics
        // (metrics might be delayed or inaccurate, and meeting room might still be open)
        try {
            const metrics = await getMeetingMetrics(meetingId);
            const zoomStatus = meeting.status ? meeting.status.toLowerCase() : '';
            
            if (zoomStatus === 'started') {
                // Zoom API says "started" - trust that over metrics
                // Meeting room is still open even if metrics say it ended
                status = 'in_progress';
                isLive = true;
                zoomLog('📊 Zoom API says "started" - keeping status as in_progress (trusting Zoom over metrics)');
            } else if (metrics.success && metrics.isLive) {
                status = 'in_progress';
                isLive = true;
                zoomLog('📊 Metrics confirm meeting is live');
            } else if (status === 'in_progress' && !metrics.isLive) {
                // Meeting time suggests it should be live, but metrics say it's not
                // Could mean it hasn't started yet or already ended
                // Only override if we're in the time window
                const now = new Date();
                const startTime = meeting.start_time ? new Date(meeting.start_time) : null;
                const duration = meeting.duration || 30;
                const endTime = startTime ? new Date(startTime.getTime() + duration * 60000) : null;
                
                if (endTime && now > endTime) {
                    status = 'ended';
                    isLive = false;
                    zoomLog('📊 Metrics indicate meeting has ended');
                }
            }
        } catch (metricsError) {
            // Metrics API might not be available (requires Business+ plan)
            // Use time-based status instead
            zoomLog('⚠️ Could not get meeting metrics (may require Business+ plan):', metricsError.message);
        }
        
        return {
            success: true,
            meeting_id: meetingId,
            status: status, // 'scheduled', 'in_progress', 'ended', 'instant', 'unknown'
            isLive: isLive,
            start_time: meeting.start_time,
            duration: meeting.duration,
            topic: meeting.topic,
            join_url: meeting.join_url,
            zoom_api_status: meeting.status // Include original Zoom status for reference
        };
    } catch (error) {
        zoomError('Error getting meeting status:', error);
        return {
            success: false,
            meeting_id: meetingId,
            status: 'unknown',
            isLive: false,
            error: error.message
        };
    }
}

/**
 * Get current Zoom user account information
 * @returns {Promise<Object>} User account details
 */
async function getCurrentUser() {
    const accessToken = await getAccessToken();
    
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.zoom.us',
            path: '/v2/users/me',
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const response = JSON.parse(data);
                        zoomLog('✅ Current Zoom user account:', {
                            id: response.id,
                            email: response.email,
                            first_name: response.first_name,
                            last_name: response.last_name,
                            display_name: response.display_name,
                            account_id: response.account_id,
                            account_number: response.account_number
                        });
                        resolve(response);
                    } else {
                        zoomError('Zoom user info error:', res.statusCode, data);
                        reject(new Error(`Failed to get user info: ${res.statusCode} - ${data}`));
                    }
                } catch (error) {
                    zoomError('Error parsing Zoom user response:', error);
                    reject(new Error(`Failed to parse user response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            zoomError('Zoom user request error:', error);
            reject(new Error(`Network error getting user info: ${error.message}`));
        });

        req.end();
    });
}

module.exports = {
    getAccessToken,
    createMeeting,
    updateMeeting,
    getMeeting,
    getMeetingMetrics,
    getMeetingParticipants,
    getMeetingStatus,
    getCurrentUser
};

