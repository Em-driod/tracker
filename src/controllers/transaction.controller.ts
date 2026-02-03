import { Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { Transaction, TransactionStatus } from '../models/transaction.model';
import { Wallet } from '../models/wallet.model';
import { Category } from '../models/category.model';
import { z } from 'zod';

const createTransactionSchema = z.object({
    title: z.string(),
    description: z.string().optional(),
    categoryId: z.string(), // Reference to dynamic category
    budgetedAmount: z.number().min(0).optional(),
});

const completeTransactionSchema = z.object({
    actualAmount: z.number().positive(),
});

/**
 * Create a Planned Transaction
 */
export const createTransaction = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const data = createTransactionSchema.parse(req.body);

        const transaction = await Transaction.create({
            ...data,
            userId,
            status: TransactionStatus.PLANNED,
        });

        res.status(201).json(transaction);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Complete a Transaction (Record actual spend and deduct from wallet)
 */
export const completeTransaction = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { id } = req.params;
        const { actualAmount } = completeTransactionSchema.parse(req.body);

        const transaction = await Transaction.findOne({ _id: id, userId });
        if (!transaction) return res.status(404).json({ message: 'Transaction not found' });
        if (transaction.status === TransactionStatus.COMPLETED) {
            return res.status(400).json({ message: 'Transaction already completed' });
        }

        // Check Wallet Balance
        const wallet = await Wallet.findOne({ userId });
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
        transaction.status = TransactionStatus.COMPLETED;
        transaction.spentAt = new Date();

        await Promise.all([wallet.save(), transaction.save()]);

        res.status(200).json({
            message: 'Transaction completed and wallet updated',
            transaction,
            balance: wallet.balance
        });
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * List Transactions with Filters
 */
export const getTransactions = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { categoryId, status, startDate, endDate } = req.query;

        const query: any = { userId };

        if (categoryId) query.categoryId = categoryId;
        if (status) query.status = status;
        if (startDate || endDate) {
            query.spentAt = {};
            if (startDate) query.spentAt.$gte = new Date(startDate as string);
            if (endDate) query.spentAt.$lte = new Date(endDate as string);
        }

        const transactions = await Transaction.find(query).sort({ createdAt: -1 });
        res.status(200).json(transactions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Delete Transaction
 */
export const deleteTransaction = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { id } = req.params;

        const result = await Transaction.findOneAndDelete({ _id: id, userId });
        if (!result) return res.status(404).json({ message: 'Transaction not found' });

        res.status(200).json({ message: 'Transaction deleted' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
