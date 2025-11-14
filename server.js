const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());

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
  console.log('Client connected:', socket.id);

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
    console.log('📝 Registering:', { shortCode, uuid });
    roomCodes.set(shortCode, uuid);
    socket.emit('room_code_registered', { shortCode, uuid });
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

  // Join room
  socket.on('join_room', ({ roomId, displayName, pin }) => {
    if (!roomId || !displayName) {
      socket.emit('error', { message: 'Invalid room data' });
      return;
    }

    let room = rooms.get(roomId);
    if (!room) {
      room = { participants: [], locked: false, pin: null };
      rooms.set(roomId, room);
    }

    // Check if locked
    if (room.locked && room.pin !== pin) {
      socket.emit('error', { message: 'Invalid PIN' });
      return;
    }

    // Remove duplicates
    room.participants = room.participants.filter(
      p => p.displayName !== displayName || p.id === socket.id
    );

    const participant = {
      id: socket.id,
      displayName,
      joinedAt: Date.now(),
      muted: true,
      speaking: false,
    };

    room.participants.push(participant);
    socket.join(roomId);

    socket.to(roomId).emit('participant_joined', participant);
    socket.emit('room_joined', {
      roomId,
      participants: room.participants,
      locked: room.locked,
    });

    console.log(`${displayName} joined room ${roomId}`);
  });

  // Leave room
  socket.on('leave_room', ({ roomId }) => {
    handleLeaveRoom(socket, roomId);
  });

  // Lock room
  socket.on('lock_room', ({ roomId, pin, locked }) => {
    const room = rooms.get(roomId);
    if (!room) return;

    if (locked && pin) {
      room.locked = true;
      room.pin = pin;
      io.to(roomId).emit('room_locked', { roomId });
    } else {
      room.locked = false;
      room.pin = null;
      io.to(roomId).emit('room_unlocked', { roomId });
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
