const fs = require('fs');
const path = require('path');

// Set up separate log file for zoom actions
const zoomLogFile = 'zoom-actions.log';
let zoomLogStream = null;

// Initialize the zoom log stream
function initializeZoomLogger() {
    if (!zoomLogStream) {
        zoomLogStream = fs.createWriteStream(zoomLogFile, { flags: 'a' }); // Append mode
    }
    return zoomLogStream;
}

// Zoom logger function
function zoomLog(...args) {
    const timestamp = new Date().toISOString();
    const message = `[${timestamp}] ${args.join(' ')}\n`;
    
    const stream = initializeZoomLogger();
    stream.write(message);
    
    // Also output to console
    console.log(...args);
}

// Zoom error logger function
function zoomError(...args) {
    const timestamp = new Date().toISOString();
    const message = `[${timestamp}] ERROR: ${args.join(' ')}\n`;
    
    const stream = initializeZoomLogger();
    stream.write(message);
    
    // Also output to console
    console.error(...args);
}

// Initialize on module load
initializeZoomLogger();

module.exports = {
    zoomLog,
    zoomError,
    initializeZoomLogger
};

