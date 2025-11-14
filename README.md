# PushTalk Socket.IO Server

Standalone Socket.IO server for PushTalk walkie-talkie app.

## Features

- WebSocket & Polling support
- Room management
- WebRTC signaling
- Rate limiting
- Health check endpoints

## Deploy to Railway

1. Push this repo to GitHub
2. Go to railway.app
3. New Project → Deploy from GitHub
4. Select this repo
5. Done!

## Environment Variables

No environment variables required. Server runs on PORT provided by Railway.

## Local Development

```bash
npm install
npm start
```

Server runs on http://localhost:3001

## Health Check

- GET / - Server status
- GET /health - Health check
