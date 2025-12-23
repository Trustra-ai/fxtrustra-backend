// routes/auth.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 10,
  message: "Too many requests, try again later"
});

// Helper to create JWT
const signToken = (userId, role) => {
  return jwt.sign({ id: userId, role }, process.env.JWT_SECRET, { expiresIn: '2h' });
};

const signRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

// -------------------
// REGISTER
// -------------------
router.post(
  '/register',
  authLimiter,
  [
    body('firstName').notEmpty().withMessage('First name required'),
    body('lastName').notEmpty().withMessage('Last name required'),
    body('email').isEmail().withMessage('Valid email required'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password min 8 chars')
      .matches(/[0-9]/).withMessage('Password must include number')
      .matches(/[a-zA-Z]/).withMessage('Password must include letter'),
    body('phone').optional().isMobilePhone('any').withMessage('Valid phone required'),
    body('country').optional().isISO31661Alpha2().withMessage('Valid country code required'),
    body('currency').optional().isIn(['USD','NGN','EUR','GBP']).withMessage('Invalid currency')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { firstName, lastName, email, password, phone, country, currency } = req.body;

      const existingUser = await User.findOne({ email });
      if(existingUser) return res.status(400).json({ error: 'Email already registered' });

      const hashedPassword = await bcrypt.hash(password, 12);

      const newUser = await User.create({
        firstName,
        lastName,
        email,
        password: hashedPassword,
        phone,
        country: country || 'NG',
        currency: currency || 'USD'
      });

      const accessToken = signToken(newUser._id, newUser.role);
      const refreshToken = signRefreshToken(newUser._id);

      newUser.refreshToken = refreshToken;
      await newUser.save({ validateBeforeSave: false });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 7*24*60*60*1000
      });

      res.status(201).json({
        message: 'Registration successful',
        accessToken,
        user: { id: newUser._id, email: newUser.email, firstName: newUser.firstName, role: newUser.role }
      });
    } catch(err) {
      console.error('Registration error:', err);
      res.status(500).json({ error: err.message });
    }
  }
);

// -------------------
// LOGIN
// -------------------
router.post('/login', authLimiter, [
  body('email').isEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password required')
], async (req,res)=>{
  const errors = validationResult(req);
  if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password +refreshToken');
    if(!user) return res.status(401).json({ error: 'Invalid credentials' });
    if(user.status !== 'active') return res.status(403).json({ error: 'Account restricted' });

    const valid = await bcrypt.compare(password, user.password);
    if(!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = signToken(user._id, user.role);
    const refreshToken = signRefreshToken(user._id);

    user.refreshToken = refreshToken;
    user.lastLogin = Date.now();
    await user.save({ validateBeforeSave: false });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7*24*60*60*1000
    });

    res.json({
      message: 'Login successful',
      accessToken,
      user: { id: user._id, email: user.email, firstName: user.firstName, role: user.role, balance: user.balance, currency: user.currency }
    });

  } catch(err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------
// REFRESH TOKEN
// -------------------
router.post('/refresh-token', async (req,res)=>{
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if(!refreshToken) return res.sendStatus(401);

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    if(!user || user.refreshToken !== refreshToken) return res.sendStatus(403);

    const newAccessToken = signToken(user._id, user.role);
    res.json({ accessToken: newAccessToken });
  } catch(err) {
    console.error('Refresh token error:', err);
    res.sendStatus(401);
  }
});

// -------------------
// LOGOUT
// -------------------
router.post('/logout', async (req,res)=>{
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  if(!refreshToken) return res.sendStatus(200);

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    await User.findByIdAndUpdate(decoded.id, { refreshToken: null });
    res.clearCookie('refreshToken', { httpOnly: true, secure: process.env.NODE_ENV==='production', sameSite: 'lax' });
    res.json({ message: 'Logout successful' });
  } catch(err) {
    console.error('Logout error:', err);
    res.sendStatus(400);
  }
});

module.exports = router;
