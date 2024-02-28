const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const transferSchema = new mongoose.Schema({
  fromAccount: {
    type: String,
    required: [true, 'provide a sending account']
  },
  toBank: {
    type: String,
    required: [true, 'A user must provide a first name'],
    enum: ['FBN', 'GTB', 'OPAY', 'UNION', 'ZENITH', 'WEMA', 'UBA']
  },
  toAccount: {
    type: String,
    required: [true, 'A transaction must have an account destination']
  },
  amount: {
    type: Number,
    required: [true, 'A transaction must have an amount'],
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function(el) {
        return el > 0;
      },
      message: 'provide a valid amount'
    }
  },
  fee: {
    type: Number,
    default: 10,
    select: false
  },
  transactionType: {
    type: String,
    enum: ['Dr', 'Cr']
  },
  narration: {
    type: String,
    maxlength: [32, 'A naration should not be more than 32 characters']
  },
  createdAt: Date,
  transferExpires: Date,
  pin: {
    type: String,
    required: [true, 'Please input your pin'],
    select: false
  },
  user: {
    type: mongoose.Schema.ObjectId,
    ref: 'User',
    required: [true, 'A transfer must have a user']
  }
});

transferSchema.pre('save', async function(next) {
  // Only run this function if pin was actually modified
  if (!this.isModified('pin')) return next();

  // Hash the pin with cost of 12
  this.pin = await bcrypt.hash(this.pin, 12);

  // Delete confirmPin field
  this.confirmPin = undefined;
  next();
});

transferSchema.methods.correctPin = async function(candidatePin, userPin) {
  return await bcrypt.compare(candidatePin, userPin);
};

const Transfer = mongoose.model('Transfer', transferSchema);
module.exports = Transfer;
