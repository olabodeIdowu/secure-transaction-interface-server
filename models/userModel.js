const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, 'A user must provide a first name'],
      trim: true
    },
    lastName: {
      type: String,
      required: [true, 'A user must provide a last name'],
      trim: true
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email']
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    pin: {
      type: String,
      required: [true, 'Please provide a pin'],
      minlength: [4, 'minimum of 4 numbers'],
      maxlength: [4, 'maximum of 4 numbers'],
      select: false
    },
    confirmPin: {
      type: String,
      required: [true, 'Please confirm your pin'],
      validate: {
        // This only works on CREATE and SAVE!!!
        validator: function(el) {
          return el === this.pin;
        },
        message: 'pins are not the same!'
      }
    },
    bank: {
      type: String,
      required: [true, 'A user must provide a bank name'],
      enum: ['FBN', 'GTB', 'OPAY', 'UNION', 'ZENITH', 'WEMA', 'UBA']
    },
    balance: {
      type: Number,
      default: 1000000
    },
    movements: [Number],
    history: Array,
    phone: {
      type: String,
      required: [true, 'A user must provide a phone number'],
      unique: true,
      validate: {
        // This only works on CREATE and SAVE!!!
        // /^\d+$/.test(el) This make sure phone number is only numbers
        validator: function(el) {
          return el.length === 11 && el.startsWith(0) && /^\d+$/.test(el);
        },
        message: 'phone number is not valid'
      }
    },
    accountNumber: {
      type: String,
      unique: true
    },
    createdAt: {
      type: Date,
      default: Date.now(),
      select: false
    },
    loggedInAt: {
      type: Date,
      select: false
    },
    loggedOutAt: {
      type: Date,
      select: false
    },
    loggedIn: {
      type: Boolean,
      default: false,
      select: false
    },
    loggedOut: {
      type: Boolean,
      default: false,
      select: false
    },
    pinChangedAt: Date,
    pinResetToken: String,
    pinResetExpires: Date,
    emailOtp: String,
    emailOtpExpires: Date,
    emailVerified: {
      type: Boolean,
      default: false
    },
    active: {
      type: Boolean,
      default: true,
      select: false
    }
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

userSchema.index({ transfer: 1, accountNumber: 1 });

// Virtual populate
userSchema.virtual('transfer', {
  ref: 'Transfer',
  foreignField: 'user',
  localField: '_id'
});

userSchema.pre('save', function(next) {
  if (!this.isModified('pin') || this.isNew) return next();

  this.pinChangedAt = Date.now() - 1000;
  next();
});

userSchema.pre(/^find/, function(next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  next();
});

userSchema.pre(/^find/, function(next) {
  // this points to the current query
  this.populate({ path: 'transfer' });

  next();
});

userSchema.pre('save', async function(next) {
  // Only run this function if pin was actually modified
  if (!this.isModified('pin')) return next();

  // Hash the pin with cost of 12
  this.pin = await bcrypt.hash(this.pin, 12);

  // Delete confirmPin field
  this.confirmPin = undefined;
  next();
});

userSchema.pre('save', async function(next) {
  // Only run this function if phone was actually modified
  if (!this.isModified('phone')) return next();

  // create an account number for user
  this.accountNumber = this.phone.slice(1);

  next();
});

userSchema.methods.generateEmailOTP = function() {
  let digits = '0123456789';
  let OTP = '';

  for (let i = 0; i < 6; i++) {
    OTP += digits[Math.floor(Math.random() * 10)];
  }

  // Hash the emailOTP with cost of 12
  this.emailOtp = crypto
    .createHash('sha256')
    .update(OTP)
    .digest('hex');

  // set emailOTP expire time
  this.emailOtpExpires = new Date(new Date().getTime() + 10 * 60 * 1000);

  return OTP;
};

userSchema.methods.correctPin = async function(candidatePin, userPin) {
  return await bcrypt.compare(candidatePin, userPin);
};

userSchema.methods.changedPinAfter = function(JWTTimestamp) {
  if (this.pinChangedAt) {
    const changedTimestamp = parseInt(this.pinChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  // False means NOT changed
  return false;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
