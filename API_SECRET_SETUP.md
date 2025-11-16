# API Secret Setup Guide

## Overview
The API secret provides authentication between the client and server, preventing unauthorized access to your Socket.IO server.

## Setup Instructions

### 1. Generate a Strong Secret
```bash
# On Mac/Linux
openssl rand -base64 32

# Or use Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### 2. Server Setup (pushtalk-server)

Create `.env` file:
```bash
cp .env.example .env
```

Edit `.env` and set your secret:
```env
API_SECRET=your-generated-secret-here
PORT=3000
```

### 3. Client Setup (walkietalkie)

Edit `.env.local`:
```env
NEXT_PUBLIC_API_SECRET=your-generated-secret-here
NEXT_PUBLIC_SOCKET_URL=https://your-server.railway.app
```

**IMPORTANT:** The API_SECRET must be EXACTLY the same on both client and server!

### 4. Railway Deployment

Add environment variable in Railway dashboard:
```
API_SECRET=your-generated-secret-here
```

### 5. Vercel Deployment

Add environment variable in Vercel dashboard:
```
NEXT_PUBLIC_API_SECRET=your-generated-secret-here
```

## Security Best Practices

1. ✅ **Never commit** `.env` files to Git
2. ✅ **Use different secrets** for development and production
3. ✅ **Rotate secrets** periodically (every 90 days)
4. ✅ **Use strong secrets** (at least 32 characters)
5. ✅ **Keep secrets private** - don't share in chat/email

## Testing

### Test Connection:
```bash
# Server logs should show:
✅ API authentication successful

# If authentication fails:
❌ Connection rejected: Invalid API secret
```

## Troubleshooting

### "Authentication required" error
- Check that `NEXT_PUBLIC_API_SECRET` is set in client `.env.local`
- Verify the secret is not empty

### "Invalid authentication" error
- Ensure secrets match EXACTLY on client and server
- Check for extra spaces or line breaks
- Secrets are case-sensitive

### Connection works locally but not on Railway
- Add `API_SECRET` to Railway environment variables
- Redeploy after adding the variable
- Check Railway logs for authentication messages

## Example Secrets

❌ **Bad (weak):**
```
API_SECRET=123456
API_SECRET=password
API_SECRET=secret
```

✅ **Good (strong):**
```
API_SECRET=K7x9mP2nQ5wR8tY1uI4oP6aS3dF7gH0jK9lZ2xC5vB8nM1qW4eR7tY0uI3oP6aS
```

## How It Works

1. Client connects with API secret in auth header
2. Server validates secret using middleware
3. If valid → connection allowed
4. If invalid → connection rejected

This prevents:
- ✅ Unauthorized clients from connecting
- ✅ Spam/abuse from unknown sources
- ✅ Direct server access without proper credentials
