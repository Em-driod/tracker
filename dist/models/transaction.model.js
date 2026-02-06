"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = exports.TransactionStatus = void 0;
const mongoose_1 = require("mongoose");
var TransactionStatus;
(function (TransactionStatus) {
    TransactionStatus["PLANNED"] = "PLANNED";
    TransactionStatus["COMPLETED"] = "COMPLETED";
})(TransactionStatus || (exports.TransactionStatus = TransactionStatus = {}));
const transactionSchema = new mongoose_1.Schema({
    userId: { type: mongoose_1.Schema.Types.ObjectId, ref: 'User', required: true },
    categoryId: { type: mongoose_1.Schema.Types.ObjectId, ref: 'Category', required: true },
    title: { type: String, required: true },
    description: { type: String },
    budgetedAmount: { type: Number, required: true, default: 0 },
    actualAmount: { type: Number, required: true, default: 0 },
    status: {
        type: String,
        required: true,
        enum: Object.values(TransactionStatus),
        default: TransactionStatus.PLANNED
    },
    spentAt: { type: Date, default: Date.now },
}, { timestamps: true });
exports.Transaction = (0, mongoose_1.model)('Transaction', transactionSchema);
