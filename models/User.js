const mongoose = require('mongoose');
const validator = require('validator');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true, // SINGLE unique index (no duplicates)
    trim: true,
    lowercase: true,
    validate: [validator.isEmail, "Please provide valid email"]
  },
  password_hash: {
    type: String,
    required: true
  },
  is_admin: {
    type: Boolean,
    default: false
  },
  balance: {
    type: Number,
    default: 0,
    min: 0
  }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
