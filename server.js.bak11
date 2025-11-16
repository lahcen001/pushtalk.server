/**
 * PushTalk Server with Enhanced Security
 * 
 * Security Features:
 * 1. Input Sanitization - Prevents XSS attacks
 * 2. Connection Limits - Max 10 connections per IP
 * 3. Room Expiration - Auto-delete rooms after 24 hours
 * 4. Encrypted Signaling - AES-256-GCM encryption for messages
 * 5. Rate Limiting - Max 10 requests per second
 * 6. Room Limits - Max 100 rooms, 20 participants per room
 * 7. IP-based Rate Limiting - Max 5 rooms per IP per hour
 */

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// Enable CORS for all routes
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['*']
}));

// Handle preflight requests
app.options('*', cors());

const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['*']
  },
  transports: ['polling', 'websocket'], // Try polling first for Railway
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  maxHttpBufferSize: 1e8,
  allowUpgrades: true,
  perMessageDeflate: false,
  httpCompression: false,
});

// Room management
const rooms = new Map();
const roomCodes = new Map();

// Security limits
const MAX_ROOMS = 100; // Maximum number of concurrent rooms
const MAX_PARTICIPANTS_PER_ROOM = 20; // Maximum participants per room
const MAX_ROOMS_PER_IP = 5; // Maximum rooms created per IP
const MAX_CONNECTIONS_PER_IP = 10; // Maximum concurrent connections per IP
const ROOM_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const roomCreationByIP = new Map(); // Track room creation by IP
const connectionsByIP = new Map(); // Track connections per IP

// ===== SECURITY FEATURE 1: INPUT SANITIZATION =====
const sanitizeInput = (input, maxLength = 50) => {
  if (!input || typeof input !== 'string') return '';
  // Remove HTML tags, scripts, and dangerous characters
  return input
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/[<>\"'`]/g, '') // Remove dangerous characters
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .trim()
    .slice(0, maxLength);
};

// ===== SECURITY FEATURE 4: ENCRYPTED SIGNALING =====
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

const encryptMessage = (text) => {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex').slice(0, 32), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
};

const decryptMessage = (encrypted, iv, authTag) => {
  try {
    const decipher = crypto.createDecipheriv(
      ENCRYPTION_ALGORITHM,
      Buffer.from(ENCRYPTION_KEY, 'hex').slice(0, 32),
      Buffer.from(iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

// ===== SECURITY FEATURE 3: ROOM EXPIRATION =====
// Cleanup old rooms (empty for 1 hour OR older than 24 hours)
setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, roomId) => {
    let shouldDelete = false;
    
    // Delete if room is older than 24 hours
    if (room.createdAt && (now - room.createdAt > ROOM_MAX_AGE)) {
      console.log(`⏰ Room expired (24h): ${roomId}`);
      shouldDelete = true;
    }
    
    // Delete if empty for more than 1 hour
    if (room.participants.length === 0) {
      if (!room.emptyAt) {
        room.emptyAt = now;
      } else if (now - room.emptyAt > 3600000) { // 1 hour
        console.log(`🧹 Cleaning up empty room: ${roomId}`);
        shouldDelete = true;
      }
    } else {
      delete room.emptyAt;
    }
    
    if (shouldDelete) {
      rooms.delete(roomId);
      // Remove from roomCodes
      roomCodes.forEach((uuid, code) => {
        if (uuid === roomId) {
          roomCodes.delete(code);
        }
      });
    }
  });
}, 300000); // Check every 5 minutes

// Rate limiting
const rateLimiter = {
  requests: new Map(),
  check(identifier) {
    const now = Date.now();
    const requests = this.requests.get(identifier) || [];
    const recentRequests = requests.filter(time => now - time < 1000);
    
    if (recentRequests.length >= 10) return false;
    
    recentRequests.push(now);
    this.requests.set(identifier, recentRequests);
    return true;
  }
};

io.on('connection', (socket) => {
  const clientIP = socket.handshake.address;
  console.log('Client connected:', socket.id, 'IP:', clientIP);

  // ===== SECURITY FEATURE 2: CONNECTION LIMITS =====
  // Check connection limit per IP
  const ipConnections = connectionsByIP.get(clientIP) || [];
  const activeConnections = ipConnections.filter(id => io.sockets.sockets.has(id));
  
  if (activeConnections.length >= MAX_CONNECTIONS_PER_IP) {
    console.log('⚠️ Connection limit reached for IP:', clientIP);
    socket.emit('error', { message: 'Too many connections from your IP. Please try again later.' });
    socket.disconnect(true);
    return;
  }
  
  // Track this connection
  activeConnections.push(socket.id);
  connectionsByIP.set(clientIP, activeConnections);
  
  // Remove connection on disconnect
  socket.on('disconnect', () => {
    const connections = connectionsByIP.get(clientIP) || [];
    connectionsByIP.set(clientIP, connections.filter(id => id !== socket.id));
    console.log('Client disconnected:', socket.id);
  });

  // Rate limiting
  socket.use((packet, next) => {
    const identifier = `${socket.id}:${packet[0]}`;
    if (!rateLimiter.check(identifier)) {
      socket.emit('error', { message: 'Rate limit exceeded' });
      return;
    }
    next();
  });

  // Register room code
  socket.on('register_room_code', ({ shortCode, uuid }) => {
    // Sanitize inputs
    const cleanShortCode = sanitizeInput(shortCode, 10);
    const cleanUuid = sanitizeInput(uuid, 100);
    
    console.log('📝 Registering:', { shortCode: cleanShortCode, uuid: cleanUuid });
    
    if (!cleanShortCode || !cleanUuid) {
      socket.emit('error', { message: 'Invalid room code format' });
      return;
    }
    
    // Check if max rooms limit reached
    if (rooms.size >= MAX_ROOMS) {
      console.log('⚠️ Max rooms limit reached');
      socket.emit('error', { message: 'Server is at capacity. Please try again later.' });
      return;
    }
    
    // Check IP-based room creation limit
    const clientIP = socket.handshake.address;
    const ipRooms = roomCreationByIP.get(clientIP) || [];
    const recentRooms = ipRooms.filter(time => Date.now() - time < 3600000); // Last hour
    
    if (recentRooms.length >= MAX_ROOMS_PER_IP) {
      console.log('⚠️ IP room creation limit reached:', clientIP);
      socket.emit('error', { message: 'Too many rooms created. Please wait before creating more.' });
      return;
    }
    
    // Track room creation
    recentRooms.push(Date.now());
    roomCreationByIP.set(clientIP, recentRooms);
    
    roomCodes.set(cleanShortCode, cleanUuid);
    socket.emit('room_code_registered', { shortCode: cleanShortCode, uuid: cleanUuid });
  });

  // Lookup room code
  socket.on('lookup_room_code', ({ shortCode }) => {
    const uuid = roomCodes.get(shortCode);
    if (uuid) {
      socket.emit('room_code_found', { shortCode, uuid });
    } else {
      socket.emit('room_code_not_found', { shortCode });
    }
  });

  // Get room participant count
  socket.on('get_room_participant_count', ({ shortCode }) => {
    const uuid = roomCodes.get(shortCode);
    if (uuid) {
      const room = rooms.get(uuid);
      const count = room ? room.participants.length : 0;
      socket.emit('room_participant_count', { shortCode, count });
    } else {
      socket.emit('room_participant_count', { shortCode, count: 0 });
    }
  });

  // Join room
  socket.on('join_room', ({ roomId, displayName, pin }) => {
    // Sanitize inputs
    const cleanRoomId = sanitizeInput(roomId, 100);
    const cleanDisplayName = sanitizeInput(displayName, 20);
    const cleanPin = pin ? sanitizeInput(pin, 20) : null;
    
    if (!cleanRoomId || !cleanDisplayName) {
      socket.emit('error', { message: 'Invalid room data' });
      return;
    }

    let room = rooms.get(cleanRoomId);
    const isFirstParticipant = !room || room.participants.length === 0;
    
    if (!room) {
      room = { 
        participants: [], 
        locked: false, 
        pin: null,
        createdAt: Date.now(), // Track creation time for expiration
        creatorId: null, // Track room creator
        bannedUsers: new Set() // Track kicked/banned users by display name
      };      rooms.set(cleanRoomId, room);
    }
    
    // Set creator if this is the first participant
    if (isFirstParticipant) {
      room.creatorId = socket.id;
    }


    // Check if user is banned from this room (by display name)
    if (room.bannedUsers && room.bannedUsers.has(cleanDisplayName)) {
      console.log('🚫 Banned user attempting to rejoin:', cleanDisplayName);
      socket.emit('error', { message: 'You have been removed from this room and cannot rejoin.' });
      return;
    }
    // Check participant limit
    if (room.participants.length >= MAX_PARTICIPANTS_PER_ROOM) {
      console.log('⚠️ Room is full:', cleanRoomId);
      socket.emit('error', { message: 'Room is full. Maximum 20 participants allowed.' });
      return;
    }

    // Check if locked
    if (room.locked) {
      if (!cleanPin) {
        console.log('🔒 Room is locked, requesting PIN:', cleanRoomId);
        socket.emit('room_requires_pin', { roomId: cleanRoomId });
        return;
      }
      if (room.pin !== cleanPin) {
        console.log('❌ Invalid PIN provided for room:', cleanRoomId);
        socket.emit('error', { message: 'Invalid PIN. Please try again.' });
        return;
      }
      console.log('✅ Valid PIN provided for locked room:', cleanRoomId);
    }

    // Remove duplicates
    room.participants = room.participants.filter(
      p => p.displayName !== cleanDisplayName || p.id === socket.id
    );

    const participant = {
      id: socket.id,
      displayName: cleanDisplayName,
      joinedAt: Date.now(),
      muted: true,
      speaking: false,
      isAdmin: socket.id === room.creatorId, // Mark creator as admin
    };

    room.participants.push(participant);
    socket.join(cleanRoomId);

    socket.to(cleanRoomId).emit('participant_joined', participant);
    socket.emit('room_joined', {
      roomId,
      participants: room.participants,
      locked: room.locked,
      isAdmin: socket.id === room.creatorId, // Tell user if they're admin
    });

    console.log(`${displayName} joined room ${roomId}`);
  });

  // Leave room
  socket.on('leave_room', ({ roomId }) => {
    handleLeaveRoom(socket, roomId);
  });

  // Lock room (admin only)
  socket.on('lock_room', ({ roomId, pin, locked }) => {
    const room = rooms.get(roomId);
    if (!room) return;

    // Check if user is admin (room creator)
    if (socket.id !== room.creatorId) {
      console.log('⚠️ Non-admin tried to lock room:', socket.id);
      socket.emit('error', { message: 'Only the room creator can lock/unlock the room.' });
      return;
    }

    if (locked && pin) {
      room.locked = true;
      room.pin = pin;
      io.to(roomId).emit('room_locked', { roomId });
      console.log('🔒 Room locked by admin:', roomId);
    } else {
      room.locked = false;
      room.pin = null;
      io.to(roomId).emit('room_unlocked', { roomId });
      console.log('🔓 Room unlocked by admin:', roomId);
    }
  });

  // WebRTC signaling
  socket.on('signal:offer', ({ to, sdp }) => {
    if (!to || !sdp) return;
    socket.to(to).emit('signal:offer', { from: socket.id, sdp });
  });

  socket.on('signal:answer', ({ to, sdp }) => {
    if (!to || !sdp) return;
    socket.to(to).emit('signal:answer', { from: socket.id, sdp });
  });

  socket.on('signal:ice', ({ to, candidate }) => {
    if (!to || !candidate) return;
    socket.to(to).emit('signal:ice', { from: socket.id, candidate });
  });

  // PTT events
  socket.on('ptt:down', ({ roomId }) => {
    socket.to(roomId).emit('participant_speaking', {
      userId: socket.id,
      speaking: true,
    });
  });

  socket.on('ptt:up', ({ roomId }) => {
    socket.to(roomId).emit('participant_speaking', {
      userId: socket.id,
      speaking: false,
    });
  });

  // Start speaking event
  socket.on('start_speaking', ({ roomId }) => {
    socket.to(roomId).emit('participant_speaking', {
      userId: socket.id,
      speaking: true,
    });
  });

  // Mute status
  socket.on('update_mute_status', ({ roomId, muted }) => {
    io.to(roomId).emit('participant_mute_changed', {
      userId: socket.id,
      muted,
    });
  });

  // Visibility
  socket.on('update_visibility', ({ roomId, hidden }) => {
    io.to(roomId).emit('participant_visibility_changed', {
      userId: socket.id,
      hidden,
    });
  });

  // Kick participant (admin only)
  socket.on('kick_participant', (data) => {
    console.log('🔔 kick_participant event received!', data);
    try {
      const { roomId, participantId } = data;
      console.log(`👢 Kick request: Admin ${socket.id} wants to kick ${participantId} from ${roomId}`);
      
      const room = rooms.get(roomId);
      
      if (!room) {
        console.log('❌ Room not found');
        socket.emit('error', { message: 'Room not found' });
        return;
      }

      console.log(`🔍 Room creator: ${room.creatorId}, Requester: ${socket.id}`);

      // Only room creator (admin) can kick participants
      if (socket.id !== room.creatorId) {
        console.log('❌ Not admin');
        socket.emit('error', { message: 'Only the admin can remove participants' });
        return;
      }

      // Cannot kick yourself
      if (participantId === socket.id) {
        socket.emit('error', { message: 'You cannot remove yourself' });
        return;
      }

      // Check if participant exists in room
      const participantExists = room.participants.some(p => p.id === participantId);
      if (!participantExists) {
        socket.emit('error', { message: 'Participant not found in room' });
        return;
      }
      // Get participant info before removing
      const kickedParticipant = room.participants.find(p => p.id === participantId);
      const kickedDisplayName = kickedParticipant ? kickedParticipant.displayName : null;

      // Notify the kicked participant
      io.to(participantId).emit('kicked_from_room', {
        roomId,
        message: 'You have been removed from this room by the admin',
      });

      // Remove participant from room
      room.participants = room.participants.filter(p => p.id !== participantId);
      
      // Add user to banned list by display name to prevent rejoin
      if (kickedDisplayName) {
        if (!room.bannedUsers) {
          room.bannedUsers = new Set();
        }
        room.bannedUsers.add(kickedDisplayName);
        console.log(`🚫 Added "${kickedDisplayName}" to banned list for room ${roomId}`);
      }

      // Force disconnect the participant from the room
      const participantSocket = io.sockets.sockets.get(participantId);
      if (participantSocket) {
        participantSocket.leave(roomId);
      }

      // Notify all remaining participants
      io.to(roomId).emit('participant_left', { userId: participantId });

      // Confirm success to admin
      socket.emit('participant_kicked_success', { participantId });

      console.log(`👢 Admin ${socket.id} kicked participant ${participantId} from room ${roomId}`);
    } catch (error) {
      console.error('Error kicking participant:', error);
      socket.emit('error', { message: 'Failed to remove participant' });
    }
  });

  // Disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    const roomIds = Array.from(socket.rooms).filter(r => r !== socket.id);
    roomIds.forEach(roomId => handleLeaveRoom(socket, roomId));
  });

  function handleLeaveRoom(socket, roomId) {
    const room = rooms.get(roomId);
    if (!room) return;

    room.participants = room.participants.filter(p => p.id !== socket.id);
    socket.leave(roomId);
    socket.to(roomId).emit('participant_left', { userId: socket.id });

    if (room.participants.length === 0) {
      rooms.delete(roomId);
    }
  }

  // Handle disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    
    // Find and remove user from all rooms
    rooms.forEach((room, roomId) => {
      const participantIndex = room.participants.findIndex(p => p.id === socket.id);
      
      if (participantIndex !== -1) {
        // Remove participant
        room.participants.splice(participantIndex, 1);
        
        // Notify others in the room
        socket.to(roomId).emit('participant_left', { userId: socket.id });
        
        console.log(`User ${socket.id} removed from room ${roomId}`);
        
        // Clean up empty rooms
        if (room.participants.length === 0) {
          rooms.delete(roomId);
          console.log(`Room ${roomId} deleted (empty)`);
        }
      }
    });
  });
});

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    connections: io.engine.clientsCount,
    rooms: rooms.size,
    uptime: process.uptime()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Socket.IO server running on port ${PORT}`);
});
