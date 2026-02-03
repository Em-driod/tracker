import { Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { Transaction, TransactionStatus } from '../models/transaction.model';
import { Category } from '../models/category.model';

/**
 * Get Budget vs Spent Data for Bar Charts
 * Now uses Category budgets as the baseline.
 */
export const getBudgetVsSpent = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { parentId } = req.query; // If provided, only show sub-categories

        let categoryQuery: any = { userId };
        if (parentId) categoryQuery.parent = parentId;

        const categories = await Category.find(categoryQuery);

        const data = await Promise.all(categories.map(async (cat) => {
            const transactions = await Transaction.find({
                userId,
                categoryId: cat._id,
                status: TransactionStatus.COMPLETED
            });

            const spent = transactions.reduce((acc, curr) => acc + curr.actualAmount, 0);

            return {
                label: cat.name,
                budget: cat.budget,
                spent: spent,
                variance: cat.budget - spent
            };
        }));

        res.status(200).json(data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Get Category Breakdown for Pie Charts
 */
export const getCategorySummary = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const data = await Transaction.aggregate([
            { $match: { userId: (req.user as any).userId, status: TransactionStatus.COMPLETED } },
            {
                $lookup: {
                    from: 'categories',
                    localField: 'categoryId',
                    foreignField: '_id',
                    as: 'categoryInfo'
                }
            },
            { $unwind: '$categoryInfo' },
            { $group: { _id: '$categoryInfo.name', value: { $sum: '$actualAmount' } } },
            { $project: { name: '$_id', value: 1, _id: 0 } }
        ]);
        res.status(200).json(data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Get Spending Trends (Daily, Weekly, Monthly, Yearly)
 */
export const getSpendingTrends = async (req: CustomRequest, res: Response) => {
    try {
        const userId = (req.user as any).userId;
        const { period = 'daily', startDate, endDate, categoryId } = req.query;

        const match: any = { userId }; // Include both PLANNED and COMPLETED for full budget view

        if (categoryId) match.categoryId = categoryId;

        if (startDate || endDate) {
            match.spentAt = {};
            if (startDate) match.spentAt.$gte = new Date(startDate as string);
            if (endDate) match.spentAt.$lte = new Date(endDate as string);
        }

        let groupId: any;
        let sortId: any;

        if (period === 'daily') {
            groupId = { year: { $year: '$spentAt' }, month: { $month: '$spentAt' }, day: { $dayOfMonth: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.month': 1, '_id.day': 1 };
        } else if (period === 'weekly') {
            groupId = { year: { $year: '$spentAt' }, week: { $week: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.week': 1 };
        } else if (period === 'monthly') {
            groupId = { year: { $year: '$spentAt' }, month: { $month: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.month': 1 };
        } else {
            // Yearly
            groupId = { year: { $year: '$spentAt' } };
            sortId = { '_id.year': 1 };
        }

        const stats = await Transaction.aggregate([
            { $match: match },
            {
                $group: {
                    _id: groupId,
                    spent: { $sum: '$actualAmount' },
                    budget: { $sum: '$budgetedAmount' }
                }
            },
            { $sort: sortId }
        ]);

        const formatted = stats.map(s => {
            let label = '';
            if (period === 'daily') {
                label = `${s._id.year}-${String(s._id.month).padStart(2, '0')}-${String(s._id.day).padStart(2, '0')}`;
            } else if (period === 'weekly') {
                label = `${s._id.year}-W${s._id.week}`;
            } else if (period === 'monthly') {
                label = `${s._id.year}-${String(s._id.month).padStart(2, '0')}`;
            } else {
                label = `${s._id.year}`;
            }
            return { label, spent: s.spent, budget: s.budget };
        });

        res.status(200).json(formatted);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
