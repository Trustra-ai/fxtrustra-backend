// routes/admin.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Middleware to verify admin
const verifyAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if(!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if(decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

    req.adminId = decoded.id;
    next();
  } catch(err) {
    console.error('Admin auth error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// -------------------
// GET ALL USERS
// -------------------
router.get('/users', verifyAdmin, async (req,res)=>{
  try {
    const users = await User.find().select('-password -refreshToken');
    res.json({ users });
  } catch(err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// -------------------
// UPDATE USER BALANCE
// -------------------
router.put('/users/:id/balance', verifyAdmin, async (req,res)=>{
  try {
    const { balance } = req.body;
    if(balance == null) return res.status(400).json({ error: 'Balance required' });

    const user = await User.findByIdAndUpdate(req.params.id, { balance }, { new:true }).select('-password -refreshToken');
    if(!user) return res.status(404).json({ error: 'User not found' });

    res.json({ message: 'Balance updated', user });
  } catch(err) {
    console.error('Update balance error:', err);
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

// -------------------
// BLOCK / UNBLOCK USER
// -------------------
router.put('/users/:id/status', verifyAdmin, async (req,res)=>{
  try {
    const { status } = req.body;
    if(!['active','blocked','pending_verification'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const user = await User.findByIdAndUpdate(req.params.id, { status }, { new:true }).select('-password -refreshToken');
    if(!user) return res.status(404).json({ error: 'User not found' });

    res.json({ message: 'User status updated', user });
  } catch(err) {
    console.error('Update status error:', err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

module.exports = router;
