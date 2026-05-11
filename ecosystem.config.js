const os = require('os');
const path = require('path');

function expandHomePath(inputPath) {
  const value = String(inputPath || '').trim();
  if (value === '~') return os.homedir();
  if (value.startsWith('~/') || value.startsWith('~\\')) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

const logDir = process.env.PM2_LOG_DIR
  ? path.resolve(expandHomePath(process.env.PM2_LOG_DIR))
  : path.join(os.homedir(), '.pm2', 'logs');

module.exports = {
  apps: [{
    name: 'codexauth',
    script: './server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '256M',
    env: {
      NODE_ENV: 'production',
      PORT: 8801
    },
    log_file: path.join(logDir, 'codexauth-combined.log'),
    out_file: path.join(logDir, 'codexauth-out.log'),
    error_file: path.join(logDir, 'codexauth-error.log')
  }]
};
