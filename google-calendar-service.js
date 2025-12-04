const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');

// ========================================
// GOOGLE CALENDAR API SETUP
// ========================================

// OAuth2 Client Configuration
// Get these from Google Cloud Console: https://console.cloud.google.com/
// MUST be set via environment variables - never hardcode secrets
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  throw new Error('Google OAuth credentials must be set via GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables');
}

const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:4500/api/google-calendar/callback';

// Scopes required for Calendar API
const SCOPES = ['https://www.googleapis.com/auth/calendar.events'];

// Token storage file (in production, use a database)
// NOTE: This stores tokens for a SINGLE user. If multiple users need access,
// implement per-user token storage (e.g., by username or session ID)
const TOKEN_FILE = path.join(__dirname, 'google-calendar-tokens.json');

/**
 * Create OAuth2 client
 */
function createOAuth2Client() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error('Google OAuth credentials not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.');
  }

  return new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
  );
}

/**
 * Load stored tokens from file
 */
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const tokens = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
      return tokens;
    }
  } catch (error) {
    console.error('Error loading tokens:', error);
  }
  return null;
}

/**
 * Save tokens to file
 */
function saveTokens(tokens) {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
    console.log('✅ Google Calendar tokens saved');
  } catch (error) {
    console.error('Error saving tokens:', error);
    throw error;
  }
}

/**
 * Get authorization URL for OAuth flow
 */
function getAuthUrl() {
  const oauth2Client = createOAuth2Client();
  
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline', // Required to get refresh token
    scope: SCOPES,
    prompt: 'consent' // Force consent screen to get refresh token
  });
  
  return authUrl;
}

/**
 * Exchange authorization code for tokens
 */
async function getTokensFromCode(code) {
  const oauth2Client = createOAuth2Client();
  
  try {
    const { tokens } = await oauth2Client.getToken(code);
    saveTokens(tokens);
    return tokens;
  } catch (error) {
    console.error('Error getting tokens:', error);
    throw error;
  }
}

/**
 * Get authenticated OAuth2 client (with refresh token handling)
 */
async function getAuthenticatedClient() {
  const tokens = loadTokens();
  
  if (!tokens) {
    throw new Error('No tokens found. Please complete OAuth flow first.');
  }
  
  const oauth2Client = createOAuth2Client();
  oauth2Client.setCredentials(tokens);
  
  // Check if token needs refresh
  if (tokens.expiry_date && Date.now() >= tokens.expiry_date) {
    console.log('🔄 Refreshing Google Calendar access token...');
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      const updatedTokens = { ...tokens, ...credentials };
      saveTokens(updatedTokens);
      oauth2Client.setCredentials(updatedTokens);
      console.log('✅ Token refreshed successfully');
    } catch (error) {
      console.error('❌ Error refreshing token:', error);
      throw new Error('Token refresh failed. Please re-authenticate.');
    }
  }
  
  return oauth2Client;
}

/**
 * Create a calendar event
 * @param {Object} eventData - Event data including optional targetCalendarEmail
 * @param {string} eventData.targetCalendarEmail - Email address of calendar to create event on (Google Workspace)
 *                                                If not provided, uses 'primary' calendar of authenticated user
 */
async function createCalendarEvent(eventData) {
  try {
    const auth = await getAuthenticatedClient();
    const calendar = google.calendar({ version: 'v3', auth });
    
    // Use targetCalendarEmail if provided (Google Workspace), otherwise use 'primary'
    const calendarId = eventData.targetCalendarEmail || 'primary';
    const organizerEmail = eventData.targetCalendarEmail || null;
    
    console.log(`📅 Creating calendar event on: ${calendarId}`);
    
    // Log which link is being used
    console.log('📅 Google Calendar Event - Link Information:');
    console.log('   zoomLink provided:', eventData.zoomLink || 'NOT PROVIDED');
    console.log('   Link type:', eventData.zoomLink && eventData.zoomLink.includes('/s/') ? 'HOST LINK ✅' : 
                eventData.zoomLink && eventData.zoomLink.includes('/j/') ? 'PARTICIPANT LINK ⚠️' : 'UNKNOWN');
    
    // Determine if zoomLink is a host link or participant link
    const isHostLink = eventData.zoomLink && eventData.zoomLink.includes('/s/');
    const linkLabel = isHostLink ? 'Host Link' : 'Join Zoom';
    
    const event = {
      summary: eventData.title || eventData.summary || 'Zoom Meeting',
      description: eventData.description || (eventData.zoomLink ? `Zoom Meeting\n\n${linkLabel}: ${eventData.zoomLink}` : ''),
      start: {
        dateTime: eventData.startTime,
        timeZone: eventData.timeZone || 'America/New_York',
      },
      end: {
        dateTime: eventData.endTime,
        timeZone: eventData.timeZone || 'America/New_York',
      },
      location: eventData.zoomLink || '',
      reminders: {
        useDefault: false,
        overrides: [
          { method: 'email', minutes: 24 * 60 }, // 24 hours before
          { method: 'popup', minutes: 15 }, // 15 minutes before
        ],
      },
      // Add organizer if targetCalendarEmail is provided (matches Python script approach)
      ...(organizerEmail && {
        organizer: {
          email: organizerEmail
        }
      }),
      // Add attendees (organizer as attendee)
      attendees: organizerEmail ? [{ email: organizerEmail }] : [],
      sendUpdates: 'all',
      sendNotifications: true,
    };
    
    // Add Zoom link to description if provided
    // CRITICAL: Check if description already contains a link (to avoid overwriting)
    // Also check if it's a host link (/s/) vs participant link (/j/)
    if (eventData.zoomLink) {
      const isHostLink = eventData.zoomLink.includes('/s/');
      const linkLabel = isHostLink ? 'Host Link' : 'Join Zoom';
      
      // If description already contains a link, append to it instead of overwriting
      if (eventData.description && (eventData.description.includes('http') || eventData.description.includes('Host Link') || eventData.description.includes('Join'))) {
        // Description already has link info, just append if needed
        if (!eventData.description.includes(eventData.zoomLink)) {
          event.description = `${eventData.description}\n\n${linkLabel}: ${eventData.zoomLink}\n${eventData.password ? `Password: ${eventData.password}` : ''}`;
        } else {
          // Link already in description, keep it as is
          event.description = eventData.description;
        }
      } else {
        // No existing link in description, add it
        event.description = `${eventData.description || 'Zoom Meeting'}\n\n${linkLabel}: ${eventData.zoomLink}\n${eventData.password ? `Password: ${eventData.password}` : ''}`;
      }
    }
    
    // Use events().import() method (like the Python script) for better Google Workspace compatibility
    // This method is designed for importing events and handles notifications better
    // Note: import() requires iCalUID field
    let response;
    if (eventData.targetCalendarEmail) {
      // For Google Workspace calendars, use import method (matches Python script)
      // Generate iCalUID if not provided (required for import method)
      if (!event.iCalUID) {
        const meetingId = eventData.meetingId || Date.now();
        event.iCalUID = `zoom-${meetingId}@zoom.us`;
      }
      console.log(`📧 Using import method for Google Workspace calendar: ${calendarId}`);
      response = await calendar.events.import({
        calendarId: calendarId,
        resource: event,
      });
    } else {
      // For primary calendar, use insert method
      response = await calendar.events.insert({
        calendarId: calendarId,
        resource: event,
      });
    }
    
    console.log('✅ Calendar event created:', response.data.htmlLink);
    return {
      success: true,
      eventId: response.data.id,
      htmlLink: response.data.htmlLink,
      event: response.data
    };
    
  } catch (error) {
    console.error('❌ Error creating calendar event:', error);
    
    if (error.code === 401) {
      // Token expired or invalid - need to re-authenticate
      return {
        success: false,
        error: 'Authentication expired. Please re-authenticate.',
        needsReauth: true
      };
    }
    
    throw error;
  }
}

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
  const tokens = loadTokens();
  return tokens && tokens.refresh_token;
}

module.exports = {
  getAuthUrl,
  getTokensFromCode,
  createCalendarEvent,
  isAuthenticated,
  SCOPES
};

