# codexauth

Local dashboard for managing Codex ChatGPT auth accounts with native OAuth and local storage.

## Run on Windows

Requirements:

- Node.js 18 or newer

Install and start:

```powershell
npm install
npm start
```

One-line install from the extracted project folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-windows.ps1
```

One-line install directly from GitHub:

```powershell
irm https://raw.githubusercontent.com/thsangyk-oss/codexauth/main/public/install-from-vps.ps1 | iex
```

The installer creates a `codexauth` desktop shortcut. Opening the shortcut starts the local server if needed, then opens the dashboard in your browser.

Open:

```text
http://localhost:8801
```

Default Windows paths:

```text
%USERPROFILE%\.codex\auth.json
```

If your Codex auth file is somewhere else, set overrides before starting:

```powershell
$env:CODEX_AUTH="$env:USERPROFILE\.codex\auth.json"
npm start
```

Optional PM2 run:

```powershell
npm install -g pm2
pm2 start ecosystem.config.js
```

Override PM2 log directory if needed:

```powershell
$env:PM2_LOG_DIR="$env:USERPROFILE\.pm2\logs"
```

## Runtime path variables

- `CODEX_AUTH`: path to Codex `auth.json`
- `CODEX_OAUTH_REDIRECT_URI`: OAuth callback URL, defaults to `http://localhost:1455/auth/callback`
- `PM2_LOG_DIR`: PM2 log directory for `ecosystem.config.js`
