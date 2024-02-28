const express = require('express');
const {
  getAllUsers,
  getUser,
  deleteUser,
  updateUser
} = require('../controllers/userController');

const {
  signup,
  login,
  verifyEmailOTP,
  forgotPin,
  resetPin,
  updatePin,
  protect,
  restrictTo,
  sendVerificationEmailOTP,
  refresh,
  logout
} = require('../controllers/authController');

const transferRouter = require('./transferRoute');

const router = express.Router();

router.use('/:userId/transfers', transferRouter);

router.post('/signup', signup);
router.post('/login', login);
router.post('/verify-email-OTP', verifyEmailOTP);
router.post('/forgot-pin', forgotPin);
router.post('/reset-pin', resetPin);
router.post('/logout', protect, logout);
router.post('/update-pin', protect, updatePin);
router.post('/send-verification-email', protect, sendVerificationEmailOTP);
router.post('/refresh', refresh);

router.route('/').get(protect, restrictTo('admin'), getAllUsers);

router
  .route('/:id')
  .get(protect, restrictTo('admin'), getUser)
  .patch(protect, restrictTo('user', 'admin'), updateUser)
  .delete(protect, restrictTo('user'), deleteUser);

module.exports = router;
