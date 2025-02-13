require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('./morganLogger');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

const app = express();

// const customFormat = '[:date[iso]] :method :url | :status | :response-time ms';
app.use(morgan);
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(limiter);

// In-memory stores
const users = [];
const refreshTokens = new Set();

// Helper function to generate tokens
const generateAccessToken = (user) => {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

const generateRefreshToken = (user) => {
  const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.add(refreshToken);
  return refreshToken;
};

// Updated middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expired' });
      }
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Register route
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (users.find((u) => u.username === username)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
      username,
      password: hashedPassword,
    });

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Updated login route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/refresh-token',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    res.json({ message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Updated logout route
app.post('/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    refreshTokens.delete(refreshToken);
  }
  res.clearCookie('token');
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});

// New refresh token route
app.post('/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokens.has(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = generateAccessToken({ username: user.username });

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 900000, // 15 minutes
    });

    res.json({ message: 'Token refreshed successfully' });
  });
});

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});
