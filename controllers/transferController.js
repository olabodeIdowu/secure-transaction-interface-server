const Transfer = require('../models/transferModel');
const User = require('../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

exports.getAllTransfer = catchAsync(async (req, res, next) => {
  const currentUser = await User.findById(req.user.id);
  if (!currentUser) next(new AppError('You are not logged In', 401));

  const transfers = await Transfer.find();
  if (!transfers) {
    return next(new AppError('no transfer found', 404));
  }

  res.status(200).json({
    status: 'success',
    dataLength: transfers.length,
    data: transfers
  });
});

exports.getTransfer = catchAsync(async (req, res, next) => {
  if (!req.params.userId) req.params.userId = req.user.id;
  const { transferId } = req.params;

  const currentUser = await User.findById(req.user.id);
  if (!currentUser) next(new AppError('You are not logged In', 401));

  const findTransfer = await Transfer.findById(transferId);

  if (!findTransfer) next(new AppError('no transfer found', 404));
  console.log(findTransfer);

  res.status(200).json({
    status: 'success',
    data: findTransfer
  });
});

exports.createTransfer = catchAsync(async (req, res, next) => {
  if (!req.params.userId) req.params.userId = req.user.id;

  const currentUser = await User.findById(req.user.id).select('+pin');
  if (!currentUser) next(new AppError('You are not logged In', 401));

  const filteredBody = filterObj(
    req.body,
    'fromAccount',
    'toBank',
    'toAccount',
    'amount',
    'narration',
    'pin'
  );

  if (!req.body.user) req.body.user = req.user.id;
  filteredBody.user = req.user.id;

  const { pin, fromAccount, toBank, toAccount, amount } = filteredBody;

  const sendingUser = await User.findOne({
    _id: req.user.id,
    accountNumber: fromAccount
  });

  const receivingUser = await User.findOne({
    bank: toBank,
    accountNumber: toAccount
  });

  // check if sending account exist
  if (!sendingUser)
    next(
      new AppError(
        'Account not found. Please check ypur bank or account number',
        404
      )
    );

  // check if receiving account exist
  if (!receivingUser) next(new AppError('Account not found', 404));

  // if amount is less than 0 and less than the user balance
  if (amount < 0 && amount > currentUser.balance) {
    return next(new AppError('inapropriate amount', 400));
  }

  // check if pin is correct
  if (!(await currentUser.correctPin(pin, currentUser.pin))) {
    return next(new AppError('Incorrect pin', 401));
  }

  // make transfer
  const newTransfer = await Transfer.create(filteredBody);

  newTransfer.createdAt = Date.now();
  newTransfer.transferExpires = new Date(Date.now() + 10 * 60 * 1000);

  await newTransfer.save({ validateBeforeSave: false });

  const transferUserBalanceLeft =
    currentUser.balance - amount - newTransfer.fee;
  const receivingUserBalanceLeft = receivingUser.balance + amount;

  // const transferMovs = currentUser.movements.push(-amount, -newTransfer.fee);
  // const receivingMovs = receivingUser.movements.push(+amount);
  // console.log(transferMovs, receivingMovs);
  const transferingAcc = await User.findByIdAndUpdate(
    currentUser.id,
    {
      balance: transferUserBalanceLeft,
      movements: [...currentUser.movements, -amount, -newTransfer.fee],
      transactionType: 'Dr',
      history: [
        ...currentUser.history,
        {
          amount: -amount,
          fee: -newTransfer.fee,
          toAccount: newTransfer.toAccount,
          createdAt: newTransfer.createdAt,
          narration: newTransfer.narration
        }
      ]
    },
    {
      new: true,
      runValidators: true
    }
  );

  const receivingAcc = await User.findByIdAndUpdate(
    receivingUser.id,
    {
      balance: receivingUserBalanceLeft,
      movements: [...receivingUser.movements, amount],
      transactionType: 'Cr',
      history: [
        ...receivingUser.history,
        {
          amount: amount,
          fromAccount: newTransfer.fromAccount,
          createdAt: newTransfer.createdAt,
          narration: newTransfer.narration
        }
      ]
    },
    {
      new: true,
      runValidators: true
    }
  );

  res.status(201).json({
    status: 'success',
    data: {
      transfer: newTransfer,
      from: transferingAcc,
      to: receivingAcc
    }
  });
});

exports.cancelTransfer = catchAsync(async (req, res, next) => {
  if (!req.params.userId) req.params.userId = req.user.id;
  const { transferId } = req.params;

  // get current user
  const currentUser = await User.findById(req.user.id);
  if (!currentUser) next(new AppError('You are not logged In', 401));

  const findTransfer = await Transfer.findOne({
    _id: transferId,
    transferExpires: { $gt: new Date(Date.now()) }
  }).select('+fee');

  if (!findTransfer) {
    return next(
      new AppError(
        'sorry, no transfer id found or the range of time at which you can revke this transaction have passed and this transaction can not be findTransferd',
        400
      )
    );
  }

  const { fromAccount, toAccount, amount, fee } = findTransfer;

  const findFromAccount = await User.findOne({ accountNumber: fromAccount });
  const findToAccount = await User.findOne({ accountNumber: toAccount });

  // const findTransferTransfer = Transfer.findById(findTransfer.id);
  const fromBalance = findFromAccount.balance + amount + fee;
  const toBalance = findToAccount.balance - amount;
  // update the two accounts
  const updatedFromAccount = await User.findByIdAndUpdate(
    findFromAccount.id,
    { balance: fromBalance },
    {
      new: true,
      runValidators: true
    }
  );

  const updatedToAccount = await User.findByIdAndUpdate(
    findToAccount.id,
    { balance: toBalance },
    {
      new: true,
      runValidators: true
    }
  );

  await Transfer.findByIdAndDelete(transferId);

  res.status(200).json({
    status: 'success',
    data: {
      from: updatedFromAccount,
      to: updatedToAccount
    }
  });
});
