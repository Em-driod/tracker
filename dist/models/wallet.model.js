"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Wallet = void 0;
const mongoose_1 = require("mongoose");
const walletOperationSchema = new mongoose_1.Schema({
    type: { type: String, required: true, enum: ['DEPOSIT', 'WITHDRAWAL', 'SPEND'] },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    reference: { type: String },
    date: { type: Date, default: Date.now },
});
const walletSchema = new mongoose_1.Schema({
    userId: { type: mongoose_1.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    balance: { type: Number, default: 0 },
    currency: { type: String, default: 'NGN' },
    history: [walletOperationSchema],
}, { timestamps: true });
exports.Wallet = (0, mongoose_1.model)('Wallet', walletSchema);
