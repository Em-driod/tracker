import { Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { Wallet } from '../models/wallet.model';
import { User } from '../models/user.model';
import { initializeTransaction, verifyTransaction } from '../services/paystack.service';
import { z } from 'zod';
import crypto from 'crypto';
import { config } from '../config';

const fundSchema = z.object({
    amount: z.number().positive(),
});

const withdrawSchema = z.object({
    amount: z.number().positive(),
    description: z.string().optional(),
});

/**
 * Get User Wallet
 */
export const getWallet = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        let wallet = await Wallet.findOne({ userId });

        if (!wallet) {
            wallet = await Wallet.create({ userId, balance: 0, history: [] });
        }

        res.status(200).json(wallet);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Initiate Funding via Paystack
 */
export const initiateFunding = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { amount } = fundSchema.parse(req.body);

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const paystackData = await initializeTransaction(user.email, amount);

        res.status(200).json({
            message: 'Funding initialized',
            ...paystackData
        });
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Handle Paystack Webhook
 */
export const handleWebhook = async (req: CustomRequest, res: Response) => {
    try {
        const hash = crypto.createHmac('sha512', config.paystack.secretKey!)
            .update(JSON.stringify(req.body))
            .digest('hex');

        if (hash !== req.headers['x-paystack-signature']) {
            return res.status(401).send();
        }

        const event = req.body;
        if (event.event === 'charge.success') {
            const { reference, amount, customer } = event.data;
            const actualAmount = amount / 100;

            const user = await User.findOne({ email: customer.email });
            if (user) {
                await Wallet.findOneAndUpdate(
                    { userId: user._id },
                    {
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
                    },
                    { upsert: true }
                );
            }
        }

        res.status(200).send();
    } catch (error) {
        console.error('Webhook Error:', error);
        res.status(500).send();
    }
};

/**
 * Withdraw Money (Simulated)
 */
export const withdraw = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { amount, description } = withdrawSchema.parse(req.body);

        const wallet = await Wallet.findOne({ userId });
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

        await wallet.save();

        res.status(200).json({ message: 'Withdrawal successful', balance: wallet.balance });
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
