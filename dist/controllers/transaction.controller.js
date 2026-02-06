"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteTransaction = exports.getTransactions = exports.completeTransaction = exports.createTransaction = void 0;
const transaction_model_1 = require("../models/transaction.model");
const wallet_model_1 = require("../models/wallet.model");
const zod_1 = require("zod");
const createTransactionSchema = zod_1.z.object({
    title: zod_1.z.string(),
    description: zod_1.z.string().optional(),
    categoryId: zod_1.z.string(), // Reference to dynamic category
    budgetedAmount: zod_1.z.number().min(0).optional(),
});
const completeTransactionSchema = zod_1.z.object({
    actualAmount: zod_1.z.number().positive(),
});
/**
 * Create a Planned Transaction
 */
const createTransaction = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const data = createTransactionSchema.parse(req.body);
        const transaction = yield transaction_model_1.Transaction.create(Object.assign(Object.assign({}, data), { userId, status: transaction_model_1.TransactionStatus.PLANNED }));
        res.status(201).json(transaction);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.createTransaction = createTransaction;
/**
 * Complete a Transaction (Record actual spend and deduct from wallet)
 */
const completeTransaction = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { id } = req.params;
        const { actualAmount } = completeTransactionSchema.parse(req.body);
        const transaction = yield transaction_model_1.Transaction.findOne({ _id: id, userId });
        if (!transaction)
            return res.status(404).json({ message: 'Transaction not found' });
        if (transaction.status === transaction_model_1.TransactionStatus.COMPLETED) {
            return res.status(400).json({ message: 'Transaction already completed' });
        }
        // Check Wallet Balance
        const wallet = yield wallet_model_1.Wallet.findOne({ userId });
        if (!wallet || wallet.balance < actualAmount) {
            return res.status(400).json({ message: 'Insufficient funds in wallet' });
        }
        // Deduct from Wallet
        wallet.balance -= actualAmount;
        wallet.history.push({
            type: 'SPEND',
            amount: actualAmount,
            description: `Spend for: ${transaction.title}`,
            reference: transaction._id.toString(),
            date: new Date()
        });
        // Update Transaction
        transaction.actualAmount = actualAmount;
        transaction.status = transaction_model_1.TransactionStatus.COMPLETED;
        transaction.spentAt = new Date();
        yield Promise.all([wallet.save(), transaction.save()]);
        res.status(200).json({
            message: 'Transaction completed and wallet updated',
            transaction,
            balance: wallet.balance
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.completeTransaction = completeTransaction;
/**
 * List Transactions with Filters
 */
const getTransactions = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { categoryId, status, startDate, endDate } = req.query;
        const query = { userId };
        if (categoryId)
            query.categoryId = categoryId;
        if (status)
            query.status = status;
        if (startDate || endDate) {
            query.spentAt = {};
            if (startDate)
                query.spentAt.$gte = new Date(startDate);
            if (endDate)
                query.spentAt.$lte = new Date(endDate);
        }
        const transactions = yield transaction_model_1.Transaction.find(query).sort({ createdAt: -1 });
        res.status(200).json(transactions);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getTransactions = getTransactions;
/**
 * Delete Transaction
 */
const deleteTransaction = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { id } = req.params;
        const result = yield transaction_model_1.Transaction.findOneAndDelete({ _id: id, userId });
        if (!result)
            return res.status(404).json({ message: 'Transaction not found' });
        res.status(200).json({ message: 'Transaction deleted' });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.deleteTransaction = deleteTransaction;
