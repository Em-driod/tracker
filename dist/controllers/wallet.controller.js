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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.withdraw = exports.handleWebhook = exports.initiateFunding = exports.getWallet = void 0;
const wallet_model_1 = require("../models/wallet.model");
const user_model_1 = require("../models/user.model");
const paystack_service_1 = require("../services/paystack.service");
const zod_1 = require("zod");
const crypto_1 = __importDefault(require("crypto"));
const config_1 = require("../config");
const fundSchema = zod_1.z.object({
    amount: zod_1.z.number().positive(),
});
const withdrawSchema = zod_1.z.object({
    amount: zod_1.z.number().positive(),
    description: zod_1.z.string().optional(),
});
/**
 * Get User Wallet
 */
const getWallet = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        let wallet = yield wallet_model_1.Wallet.findOne({ userId });
        if (!wallet) {
            wallet = yield wallet_model_1.Wallet.create({ userId, balance: 0, history: [] });
        }
        res.status(200).json(wallet);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getWallet = getWallet;
/**
 * Initiate Funding via Paystack
 */
const initiateFunding = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { amount } = fundSchema.parse(req.body);
        const user = yield user_model_1.User.findById(userId);
        if (!user)
            return res.status(404).json({ message: 'User not found' });
        const paystackData = yield (0, paystack_service_1.initializeTransaction)(user.email, amount);
        res.status(200).json(Object.assign({ message: 'Funding initialized' }, paystackData));
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.initiateFunding = initiateFunding;
/**
 * Handle Paystack Webhook
 */
const handleWebhook = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const hash = crypto_1.default.createHmac('sha512', config_1.config.paystack.secretKey)
            .update(JSON.stringify(req.body))
            .digest('hex');
        if (hash !== req.headers['x-paystack-signature']) {
            return res.status(401).send();
        }
        const event = req.body;
        if (event.event === 'charge.success') {
            const { reference, amount, customer } = event.data;
            const actualAmount = amount / 100;
            const user = yield user_model_1.User.findOne({ email: customer.email });
            if (user) {
                yield wallet_model_1.Wallet.findOneAndUpdate({ userId: user._id }, {
                    $inc: { balance: actualAmount },
                    $push: {
                        history: {
                            type: 'DEPOSIT',
                            amount: actualAmount,
                            description: 'Wallet funding via Paystack',
                            reference,
                            date: new Date()
                        }
                    }
                }, { upsert: true });
            }
        }
        res.status(200).send();
    }
    catch (error) {
        console.error('Webhook Error:', error);
        res.status(500).send();
    }
});
exports.handleWebhook = handleWebhook;
/**
 * Withdraw Money (Simulated)
 */
const withdraw = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { amount, description } = withdrawSchema.parse(req.body);
        const wallet = yield wallet_model_1.Wallet.findOne({ userId });
        if (!wallet || wallet.balance < amount) {
            return res.status(400).json({ message: 'Insufficient funds' });
        }
        wallet.balance -= amount;
        wallet.history.push({
            type: 'WITHDRAWAL',
            amount,
            description: description || 'Wallet withdrawal',
            date: new Date()
        });
        yield wallet.save();
        res.status(200).json({ message: 'Withdrawal successful', balance: wallet.balance });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.withdraw = withdraw;
