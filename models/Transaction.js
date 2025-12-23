const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal'],
    required: true
  },
  amount: {
    type: mongoose.Types.Decimal128,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    enum: ['USD', 'NGN', 'EUR', 'GBP'],
    default: 'USD'
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  approvedAt: Date,
  notes: String
}, { toJSON: { getters: true }, toObject: { getters: true }});

transactionSchema.virtual('amountFloat').get(function() {
  return parseFloat(this.amount.toString());
});

module.exports = mongoose.model('Transaction', transactionSchema);onst mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({

gebruiker: {

type: mongoose.Schema.Types.ObjectId,

ref: 'Gebruiker',

vereist: true

},

type: {

type: String,

enum: ['storting', 'opname'],

vereist: true

},

bedrag: {

type: mongoose.Types.Decimal128,

vereist: true,

min: 0

},

valuta: {

type: String,

enum: ['USD', 'NGN', 'EUR', 'GBP'],

standaard: 'USD'

},

status: {

type: String,

enum: ['in behandeling', 'goedgekeurd', 'afgewezen'],

standaard: 'in behandeling'

},

aangemaakt op: {

type: Datum,

standaard: Datum.nu

},

goedgekeurd door: {

type: mongoose.Schema.Types.ObjectId,

ref: 'Gebruiker'

},

goedgekeurd op: Datum,

opmerkingen: String
}, { toJSON: { getters: true }, toObject: { getters: true }});

transactionSchema.virtual('amountFloat').get(function() {

return parseFloat(this.amount.toString());
});

module.exports = mongoose.model('Transactie', transactionSchema);o
xmodule.exports = mongoose.model('Transaction', transactionSchema);
