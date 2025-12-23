const express = require('express');
const app = express();
require('dotenv').config();
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser'); // For refresh tokens
const cors = require('cors');

// =====================
// Database connection
// =====================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1); // Stop server if DB fails
  });

// =====================
// Middleware
// =====================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true, // Allow cookies
}));

// =====================
// Routes
// =====================
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// =====================
// Root endpoint
// =====================
app.get('/', (req, res) => {
  res.json({ status: 'active', message: 'FxTrustra backend running 🚀', timestamp: new Date() });
});

// =====================
// 404 Handler
// =====================
app.use((req, res) => {
  res.status(404).json({ error: 'Resource not found' });
});

// =====================
// Error handling
// =====================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// =====================
// Start server
// =====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ FxTrustra server running on port ${PORT}`);
});
