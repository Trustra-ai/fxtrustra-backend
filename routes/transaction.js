const express = require('express');
const router = express.Router();
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Middleware: admin verification
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
// Create Deposit / Withdrawal
// -------------------
router.post('/:type', async (req, res) => {
  try {
    const { userId, amount, currency, notes } = req.body;
    const type = req.params.type; // deposit or withdrawal

    if(!['deposit','withdrawal'].includes(type)) return res.status(400).json({ error: 'Invalid transaction type' });

    const user = await User.findById(userId);
    if(!user) return res.status(404).json({ error: 'User not found' });

    const transaction = await Transaction.create({ user: userId, type, amount, currency, notes });
    res.status(201).json({ message: `${type} created`, transaction });
  } catch(err) {
    console.error('Transaction create error:', err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------
// Get all transactions (admin only)
// -------------------
router.get('/', verifyAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('user', 'firstName lastName email')
      .populate('approvedBy', 'firstName lastName email')
      .sort({ createdAt: -1 });
    res.json({ transactions });
  } catch(err) {
    console.error('Get transactions error:', err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// -------------------
// Approve / Reject Transaction
// -------------------
router.put('/:id/status', verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body; // approved / rejected
    if(!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const transaction = await Transaction.findById(req.params.id);
    if(!transaction) return res.status(404).json({ error: 'Transaction not found' });
    if(transaction.status !== 'pending') return res.status(400).json({ error: 'Transaction already processed' });

    transaction.status = status;
    transaction.approvedBy = req.adminId;
    transaction.approvedAt = new Date();

    await transaction.save();

    // Update user balance if approved
    if(status === 'approved') {
      const user = await User.findById(transaction.user);
      if(transaction.type === 'deposit') {
        user.balance = parseFloat(user.balance || 0) + parseFloat(transaction.amount.toString());
      } else if(transaction.type === 'withdrawal') {
        user.balance = parseFloat(user.balance || 0) - parseFloat(transaction.amount.toString());
        if(user.balance < 0) user.balance = 0;
      }
      await user.save();
    }

    res.json({ message: `Transaction ${status}`, transaction });
  } catch(err) {
    console.error('Transaction status error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
