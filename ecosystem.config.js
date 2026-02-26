const path = require('path');

module.exports = {
  apps: [
    {
      name: 'crm-api',
      script: 'server.js',
      cwd: path.join(__dirname, 'server'),
      watch: false,
      restart_delay: 2000,
      max_restarts: 50,
      autorestart: true,
      env: { NODE_ENV: 'production', PORT: 3001 }
    }
  ]
}
