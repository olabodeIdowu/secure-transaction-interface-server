const express = require('express');
const {
  getAllTransfer,
  createTransfer,
  getTransfer,
  cancelTransfer
} = require('./../controllers/transferController');
const { protect, restrictTo } = require('./../controllers/authController');

const router = express.Router({ mergeParams: true });

router
  .route('/')
  .get(protect, restrictTo('admin'), getAllTransfer)
  .post(protect, restrictTo('user'), createTransfer);
router
  .route('/:transferId')
  .get(protect, restrictTo('user', 'admin'), getTransfer)
  .patch(protect, restrictTo('user', 'admin'), cancelTransfer);

module.exports = router;
