require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

/* =====================
   MIDDLEWARE
===================== */
app.use(cors());
app.use(express.json());

/* =====================
   DATABASE CONNECTION
===================== */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

/* =====================
   SCHEMAS & MODELS
===================== */
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  is_admin: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now },
});

const planSchema = new mongoose.Schema({
  name: { type: String, required: true },
  min_amount: { type: Number, required: true },
  max_amount: { type: Number },
  duration_days: { type: Number, required: true },
  roi_percentage: { type: Number, required: true },
  is_active: { type: Boolean, default: true },
  created_at: { type: Date, default: Date.now },
});

const investmentSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  amount: { type: Number, required: true },
  start_date: { type: Date, default: Date.now },
  status: { type: String, default: 'active' },
});

const User = mongoose.model('User', userSchema);
const Plan = mongoose.model('Plan', planSchema);
const Investment = mongoose.model('Investment', investmentSchema);

/* =====================
   AUTH MIDDLEWARE
===================== */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

/* =====================
   ROUTES
===================== */
app.get('/', (req, res) => {
  res.json({
    status: "active",
    message: "FxTrustra backend running 🚀",
    timestamp: new Date().toISOString()
  });
});

/* REGISTER */
app.post('/api/register', async (req, res) => {
  const { email, password, isAdmin } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });

  try {
    const exists = await User.findOne({ email });
    if (exists)
      return res.status(409).json({ message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password_hash: hashed,
      is_admin: isAdmin === true
    });

    await user.save();
    res.status(201).json({
      id: user._id,
      email: user.email,
      is_admin: user.is_admin
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* LOGIN */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });

  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, email: user.email, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* CREATE PLAN (ADMIN) */
app.post('/api/plans', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const plan = new Plan(req.body);
    await plan.save();
    res.status(201).json(plan);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* GET PLANS */
app.get('/api/plans', async (req, res) => {
  const plans = await Plan.find({ is_active: true });
  res.json(plans);
});

/* INVEST */
app.post('/api/investments', authenticateToken, async (req, res) => {
  try {
    const investment = new Investment({
      user_id: req.user.id,
      plan_id: req.body.plan_id,
      amount: req.body.amount
    });

    await investment.save();
    res.status(201).json(investment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =====================
   START SERVER
===================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
