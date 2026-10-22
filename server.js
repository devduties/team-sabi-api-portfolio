// server.js - Main backend server
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve uploaded files statically
app.use('/uploads', express.static(uploadsDir));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow images, PDFs, and common document types
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|xls|xlsx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images, PDFs, and documents are allowed.'));
    }
  }
});

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required. Set it in the environment before starting the server.');
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============================================
// AUTH ROUTES
// ============================================

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (name, email, password, avatar, status) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, avatar, status, created_at',
      [name, email, hashedPassword, name.split(' ').map(n => n[0]).join('').toUpperCase(), 'available']
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ user, token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    // Don't send password back
    delete user.password;

    res.json({ user, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, avatar, status, department, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update current user profile
app.patch('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;

    const result = await pool.query(
      'UPDATE users SET name = $1, email = $2 WHERE id = $3 RETURNING id, name, email, avatar, status, department, is_admin, created_at',
      [name, email, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password
app.patch('/api/users/me/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get current user with password
    const userResult = await pool.query(
      'SELECT password FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query(
      'UPDATE users SET password = $1 WHERE id = $2',
      [hashedPassword, req.user.id]
    );

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// USER ROUTES
// ============================================

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, avatar, status, department FROM users WHERE id != $1 ORDER BY name',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user status
app.patch('/api/users/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const result = await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, name, email, avatar, status, department',
      [status, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// CHANNEL ROUTES
// ============================================

// Get all channels for user
app.get('/api/channels', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT c.* FROM channels c
       LEFT JOIN channel_members cm ON c.id = cm.channel_id
       WHERE c.type = 'public' OR cm.user_id = $1
       ORDER BY c.name`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get channels error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create channel
app.post('/api/channels', authenticateToken, async (req, res) => {
  try {
    const { name, type, description } = req.body;
    
    const result = await pool.query(
      'INSERT INTO channels (name, type, description, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, type || 'public', description, req.user.id]
    );

    const channel = result.rows[0];

    // Add creator as member
    await pool.query(
      'INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2)',
      [channel.id, req.user.id]
    );

    res.json(channel);
  } catch (error) {
    console.error('Create channel error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update channel
app.patch('/api/channels/:channelId', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const { name, type, description } = req.body;

    const result = await pool.query(
      'UPDATE channels SET name = $1, type = $2, description = $3 WHERE id = $4 RETURNING *',
      [name, type, description, channelId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update channel error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete channel
app.delete('/api/channels/:channelId', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;

    // Check if user is admin
    const userResult = await pool.query(
      'SELECT is_admin FROM users WHERE id = $1',
      [req.user.id]
    );

    const isAdmin = userResult.rows[0]?.is_admin || false;

    if (!isAdmin) {
      return res.status(403).json({ error: 'Only admins can delete channels' });
    }

    // Delete channel (cascade will delete members and messages)
    await pool.query('DELETE FROM channels WHERE id = $1', [channelId]);

    res.json({ success: true, channelId });
  } catch (error) {
    console.error('Delete channel error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// MESSAGE ROUTES
// ============================================

// Get messages for a channel
app.get('/api/channels/:channelId/messages', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const { limit = 50, before } = req.query;

    let query = `
      SELECT m.*, u.name as user_name, u.avatar as user_avatar
      FROM messages m
      JOIN users u ON m.user_id = u.id
      WHERE m.channel_id = $1
    `;
    const params = [channelId];

    if (before) {
      query += ` AND m.created_at < $2`;
      params.push(before);
    }

    query += ` ORDER BY m.created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const result = await pool.query(query, params);
    res.json(result.rows.reverse());
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get direct messages between two users
app.get('/api/direct-messages/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 50, before } = req.query;

    let query = `
      SELECT m.*, u.name as user_name, u.avatar as user_avatar
      FROM messages m
      JOIN users u ON m.user_id = u.id
      WHERE m.channel_id IS NULL
      AND ((m.user_id = $1 AND m.recipient_id = $2) OR (m.user_id = $2 AND m.recipient_id = $1))
    `;
    const params = [req.user.id, userId];

    if (before) {
      query += ` AND m.created_at < $3`;
      params.push(before);
    }

    query += ` ORDER BY m.created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const result = await pool.query(query, params);
    res.json(result.rows.reverse());
  } catch (error) {
    console.error('Get direct messages error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Pin/unpin message
app.patch('/api/messages/:messageId/pin', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { pinned } = req.body;

    const result = await pool.query(
      'UPDATE messages SET pinned = $1 WHERE id = $2 RETURNING *',
      [pinned, messageId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Pin message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit message
app.patch('/api/messages/:messageId/edit', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { text } = req.body;

    // Check if user owns the message
    const checkResult = await pool.query(
      'SELECT user_id FROM messages WHERE id = $1',
      [messageId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (checkResult.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Not authorized to edit this message' });
    }

    const result = await pool.query(
      'UPDATE messages SET text = $1, edited = TRUE, edited_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      [text, messageId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete message
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;

    // Check if message exists and get owner
    const checkResult = await pool.query(
      'SELECT user_id FROM messages WHERE id = $1',
      [messageId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Get user's admin status
    const userResult = await pool.query(
      'SELECT is_admin FROM users WHERE id = $1',
      [req.user.id]
    );

    const isAdmin = userResult.rows[0]?.is_admin || false;
    const isOwner = checkResult.rows[0].user_id === req.user.id;

    // Allow deletion if user is owner OR admin
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ error: 'Not authorized to delete this message' });
    }

    await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);

    res.json({ success: true, messageId });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add reaction to message
app.post('/api/messages/:messageId/reactions', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;

    const result = await pool.query(
      `INSERT INTO reactions (message_id, user_id, emoji) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (message_id, user_id, emoji) DO NOTHING
       RETURNING *`,
      [messageId, req.user.id, emoji]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Add reaction error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove reaction from message
app.delete('/api/messages/:messageId/reactions/:emoji', authenticateToken, async (req, res) => {
  try {
    const { messageId, emoji } = req.params;

    await pool.query(
      'DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3',
      [messageId, req.user.id, emoji]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Remove reaction error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get reactions for a message
app.get('/api/messages/:messageId/reactions', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;

    const result = await pool.query(
      `SELECT r.*, u.name as user_name, u.avatar as user_avatar
       FROM reactions r
       JOIN users u ON r.user_id = u.id
       WHERE r.message_id = $1
       ORDER BY r.created_at`,
      [messageId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Get reactions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload file
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileUrl = `${process.env.BACKEND_URL || 'http://localhost:5000'}/uploads/${req.file.filename}`;
    
    res.json({
      file_url: fileUrl,
      file_name: req.file.originalname,
      file_type: req.file.mimetype,
      file_size: req.file.size
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Search messages
app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;

    const result = await pool.query(
      `SELECT m.*, u.name as user_name, u.avatar as user_avatar, c.name as channel_name
       FROM messages m
       JOIN users u ON m.user_id = u.id
       LEFT JOIN channels c ON m.channel_id = c.id
       WHERE m.text ILIKE $1
       AND (m.channel_id IN (
         SELECT channel_id FROM channel_members WHERE user_id = $2
         UNION
         SELECT id FROM channels WHERE type = 'public'
       ) OR m.user_id = $2 OR m.recipient_id = $2)
       ORDER BY m.created_at DESC
       LIMIT 50`,
      [`%${q}%`, req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// SOCKET.IO REAL-TIME MESSAGING
// ============================================

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Authenticate socket connection
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.id;
      socket.join(`user-${decoded.id}`);
      
      // Update user status to online
      await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['available', decoded.id]);
      
      io.emit('user_status_change', { userId: decoded.id, status: 'available' });
    } catch (error) {
      socket.emit('auth_error', 'Invalid token');
    }
  });

  // Join channel
  socket.on('join_channel', (channelId) => {
    socket.join(`channel-${channelId}`);
  });

  // Leave channel
  socket.on('leave_channel', (channelId) => {
    socket.leave(`channel-${channelId}`);
  });

  // Send message to channel
  socket.on('send_channel_message', async (data) => {
    try {
      const { channelId, text, file_url, file_name, file_type, file_size } = data;

      const result = await pool.query(
        `INSERT INTO messages (channel_id, user_id, text, file_url, file_name, file_type, file_size)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [channelId, socket.userId, text, file_url, file_name, file_type, file_size]
      );

      const message = result.rows[0];

      // Get user info
      const userResult = await pool.query(
        'SELECT name, avatar FROM users WHERE id = $1',
        [socket.userId]
      );

      const messageWithUser = {
        ...message,
        user_name: userResult.rows[0].name,
        user_avatar: userResult.rows[0].avatar
      };

      io.to(`channel-${channelId}`).emit('new_message', messageWithUser);
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('message_error', 'Failed to send message');
    }
  });

  // Send direct message
  socket.on('send_direct_message', async (data) => {
    try {
      const { recipientId, text, file_url, file_name, file_type, file_size } = data;

      const result = await pool.query(
        `INSERT INTO messages (user_id, recipient_id, text, file_url, file_name, file_type, file_size)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [socket.userId, recipientId, text, file_url, file_name, file_type, file_size]
      );

      const message = result.rows[0];

      // Get user info
      const userResult = await pool.query(
        'SELECT name, avatar FROM users WHERE id = $1',
        [socket.userId]
      );

      const messageWithUser = {
        ...message,
        user_name: userResult.rows[0].name,
        user_avatar: userResult.rows[0].avatar
      };

      // Send to both sender and recipient
      io.to(`user-${socket.userId}`).emit('new_direct_message', messageWithUser);
      io.to(`user-${recipientId}`).emit('new_direct_message', messageWithUser);
    } catch (error) {
      console.error('Send direct message error:', error);
      socket.emit('message_error', 'Failed to send message');
    }
  });

  // User is typing
  socket.on('typing', (data) => {
    const { channelId, recipientId } = data;
    if (channelId) {
      socket.to(`channel-${channelId}`).emit('user_typing', { userId: socket.userId, channelId });
    } else if (recipientId) {
      io.to(`user-${recipientId}`).emit('user_typing', { userId: socket.userId });
    }
  });

  // Disconnect
  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
    if (socket.userId) {
      await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['away', socket.userId]);
      io.emit('user_status_change', { userId: socket.userId, status: 'away' });
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
