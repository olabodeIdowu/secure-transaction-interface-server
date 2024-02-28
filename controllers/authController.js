const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const Email = require('../utils/email');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');
const catchAsync = require('../utils/catchAsync');

// const { fast2sms } = require('../utils/otpUtils');

// POST - to create a resource
// PATCH - to update a resource
// PUT - to replace a resource
// GET - to get a resource or a list of resources
// DELETE - to delete a resource
// 200 OK - the request was successful (some API calls may return 201 instead).
// 204 No Content - the request was successful but there is no representation to return (i.e. the response is empty).
// 401 Unauthorized - authentication failed or user doesn't have permissions for requested operation.
// 403 Forbidden - access denied.
// 404 Not Found - resource was not found.
// 422 Unprocessable Entity - requested data contain invalid values.

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

const signUserToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const signRefreshToken = id => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, req, res) => {
  const userToken = signUserToken(user._id);
  const refreshToken = signRefreshToken(user._id);
  // console.log(user._id === user.id);

  res.cookie('jwtToken', userToken, {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  });

  res.cookie('jwtRefreshToken', refreshToken, {
    expires: new Date(
      Date.now() +
        process.env.JWT_REFRESH_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  });

  // Remove pin from output
  user.pin = undefined;

  res.status(statusCode).json({
    status: 'success',
    userToken,
    refreshToken,
    data: {
      user
    }
  });
};

// ---------------------- signup in with email -------------------------

exports.signup = catchAsync(async (req, res, next) => {
  // 2) Filtered out unwanted fields names that are not allowed to be updated

  const filteredBody = filterObj(
    req.body,
    'email',
    'firstName',
    'bank',
    'phone',
    'lastName',
    'pin',
    'confirmPin'
  );
  const newUser = await User.create(filteredBody);

  if (!newUser) {
    return next(new AppError('requested data contain invalid values', 422));
  }

  const url = undefined;
  const emailToken = undefined;

  // send welcome email to user email address
  await new Email(newUser, url, emailToken).sendWelcome();

  // get email OTP
  const emailOTP = newUser.generateEmailOTP();

  await newUser.save({ validateBeforeSave: false });

  // send email message to confirm user email address
  await new Email(newUser, url, emailOTP).sendEmailOTP();

  res.status(201).json({
    status: 'success',
    message:
      'email containing your otp as successfully been sent to your email.'
  });
});

// ---------------------- send email verification -------------------------

exports.sendEmailVerification = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.user.email });

  if (!user) {
    return next(new AppError('user not found', 404));
  }

  // get email OTP
  const emailOTP = user.generateEmailOTP();

  await user.save({ validateBeforeSave: false });

  const url = undefined;

  // send email message to confirm user email address
  await new Email(user, url, emailOTP).sendEmailOTP();

  res.status(201).json({
    status: 'success',
    message:
      'email containing your otp as successfully been sent to your email.'
  });
});

// ---------------------- verify with email -------------------------

exports.verifyEmailOTP = catchAsync(async (req, res, next) => {
  const { emailOTP } = req.body;
  if (!emailOTP)
    return next(
      new AppError(
        'Unprocessable Entity - requested data contain invalid values.',
        422
      )
    );

  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(emailOTP)
    .digest('hex');

  const user = await User.findOne({
    emailOtp: hashedToken,
    emailOtpExpires: { $gt: new Date(Date.now()) }
  });

  // 2) If OTP has not expired, and there is user, set the new pin
  if (!user) {
    return next(new AppError('OTP is invalid or has expired', 400));
  }

  user.emailVerified = true;
  user.emailOtp = undefined;
  user.emailOtpExpires = undefined;

  await user.save({ validateBeforeSave: false });

  const url = undefined;
  const emailToken = undefined;

  await new Email(user, url, emailToken).sendEmailVerifySuccess();

  res.status(200).json({
    status: 'success',
    message: 'email as successfully been verified'
  });
});

// ---------------------- login in with email -------------------------

exports.login = catchAsync(async (req, res, next) => {
  const { email, pin } = req.body;

  // 1) Check if email and pin exist
  if (!email || !pin) {
    return next(new AppError('Please provide email and pin!', 400));
  }
  // 2) Check if user exists && pin is correct
  const user = await User.findOne({ email }).select('+pin');
  // console.log(user);
  if (!user || !(await user.correctPin(pin, user.pin))) {
    return next(new AppError('Incorrect email or pin', 401));
  }

  user.loggedInAt = new Date(Date.now());
  user.loggedIn = true;

  await user.save({ validateBeforeSave: false });

  createSendToken(user, 200, req, res);
});

// ---------------------- logout -------------------------

exports.logout = catchAsync(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  res.cookie('jwtToken', 'loggedout', {
    expires: new Date(Date.now() + 5 * 1000),
    httpOnly: true
  });

  user.loggedOutAt = new Date(Date.now());
  user.loggedOut = true;

  await user.save({ validateBeforeSave: false });

  res.status(200).json({ status: 'success' });
});

// ---------------------- protect -------------------------

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwtToken) {
    token = req.cookies.jwtToken;
  }

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  // 2) Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does no longer exist.',
        401
      )
    );
  }

  // console.log(
  //   req.headers.Authorization,
  //   req.cookies.jwtToken,
  //   currentUser,
  //   decoded
  // );

  // 4) Check if user changed pin after the token was issued
  if (currentUser.changedPinAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed pin! Please log in again.', 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  res.locals.user = currentUser;

  next();
});

// ---------------------- refresh token -------------------------

exports.refresh = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;

  if (req.headers['X-Refresh-Token']) {
    token = req.headers['X-Refresh-Token'];
  } else if (req.cookies.jwtRefreshToken) {
    token = req.cookies.jwtRefreshToken;
  }

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  // 2) Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does no longer exist.',
        401
      )
    );
  }

  createSendToken(currentUser, 200, req, res);
});

// ---------------------- logged In -------------------------
exports.isLoggedIn = catchAsync(async (req, res, next) => {
  if (req.cookies.jwtToken) {
    // 1) verify token
    const decoded = await promisify(jwt.verify)(
      req.cookies.jwtToken,
      process.env.JWT_SECRET
    );

    // 2) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError(
          'The user belonging to this token does no longer exist.',
          401
        )
      );
    }

    // 3) Check if user changed pin after the token was issued
    if (currentUser.changedPinAfter(decoded.iat)) {
      return next(
        new AppError('User recently changed pin! Please log in again.', 401)
      );
    }

    // THERE IS A LOGGED IN USER
    res.locals.user = currentUser;
    return next();
  }
  next();
});

// ---------------------- restrict to -------------------------

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

// ---------------------- forgot pin -------------------------

exports.forgotPin = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  const emailOTP = user.generateEmailOTP();
  await user.save({ validateBeforeSave: false });

  // send url and otp
  const resetUrl = `${req.protocol}://${req.get('host')}/reset-pin`;

  await new Email(user, resetUrl, emailOTP).sendPinReset();

  res.status(200).json({
    status: 'success',
    message: 'Token sent to email!'
  });
});

// ---------------------- reset pin -------------------------

exports.resetPin = catchAsync(async (req, res, next) => {
  const { emailOTP, pin, confirmPin } = req.body;
  if (!emailOTP)
    return next(
      new AppError(
        'Unprocessable Entity - requested data contain invalid values.',
        422
      )
    );

  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(emailOTP)
    .digest('hex');

  const user = await User.findOne({
    emailOtp: hashedToken,
    emailOtpExpires: { $gt: new Date(Date.now()) }
  });

  // 2) If OTP has not expired, and there is user, set the new pin
  if (!user) {
    return next(new AppError('OTP is invalid or has expired', 400));
  }

  user.pin = pin;
  user.confirmPin = confirmPin;
  user.pinChangedAt = new Date(Date.now());
  user.emailOtp = undefined;
  user.emailOtpExpires = undefined;
  await user.save();

  const url = undefined;
  const emailToken = undefined;

  await new Email(user, url, emailToken).sendPinResetSuccess();
  createSendToken(user, 200, req, res);
});

// ---------------------- update pin -------------------------

exports.updatePin = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+pin');

  // 2) Check if POSTed current pin is correct
  if (!(await user.correctPin(req.body.currentPin, user.pin))) {
    return next(new AppError('Your current pin is wrong.', 401));
  }

  // 3) If so, update pin
  user.pin = req.body.pin;
  user.confirmPin = req.body.confirmPin;
  user.pinChangedAt = new Date(Date.now());
  await user.save();

  // User.findByIdAndUpdate will NOT work as intended!
  const url = undefined;
  const emailToken = undefined;

  await new Email(user, url, emailToken).sendPinResetSuccess();
  // 4) Log user in, send JWT
  createSendToken(user, 200, req, res);
});

exports.sendVerificationEmailOTP = catchAsync(async (req, res, next) => {
  const newUser = await User.findOne({ email: req.user.email });

  if (!newUser) {
    return next(new AppError('you are not logged in!', 422));
  }

  const url = undefined;

  // get email OTP
  const emailOTP = newUser.generateEmailOTP();

  await newUser.save({ validateBeforeSave: false });

  // send email message to confirm user email address
  await new Email(newUser, url, emailOTP).sendEmailOTP();

  res.status(201).json({
    status: 'success',
    message:
      'email containing your otp as successfully been sent to your email.'
  });
});
