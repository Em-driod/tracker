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
exports.getSpendingTrends = exports.getCategorySummary = exports.getBudgetVsSpent = void 0;
const transaction_model_1 = require("../models/transaction.model");
const category_model_1 = require("../models/category.model");
/**
 * Get Budget vs Spent Data for Bar Charts
 * Now uses Category budgets as the baseline.
 */
const getBudgetVsSpent = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { parentId } = req.query; // If provided, only show sub-categories
        let categoryQuery = { userId };
        if (parentId)
            categoryQuery.parent = parentId;
        const categories = yield category_model_1.Category.find(categoryQuery);
        const data = yield Promise.all(categories.map((cat) => __awaiter(void 0, void 0, void 0, function* () {
            const transactions = yield transaction_model_1.Transaction.find({
                userId,
                categoryId: cat._id,
                status: transaction_model_1.TransactionStatus.COMPLETED
            });
            const spent = transactions.reduce((acc, curr) => acc + curr.actualAmount, 0);
            return {
                label: cat.name,
                budget: cat.budget,
                spent: spent,
                variance: cat.budget - spent
            };
        })));
        res.status(200).json(data);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getBudgetVsSpent = getBudgetVsSpent;
/**
 * Get Category Breakdown for Pie Charts
 */
const getCategorySummary = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const data = yield transaction_model_1.Transaction.aggregate([
            { $match: { userId: req.user.userId, status: transaction_model_1.TransactionStatus.COMPLETED } },
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
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getCategorySummary = getCategorySummary;
/**
 * Get Spending Trends (Daily, Weekly, Monthly, Yearly)
 */
const getSpendingTrends = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const userId = req.user.userId;
        const { period = 'daily', startDate, endDate, categoryId } = req.query;
        const match = { userId }; // Include both PLANNED and COMPLETED for full budget view
        if (categoryId)
            match.categoryId = categoryId;
        if (startDate || endDate) {
            match.spentAt = {};
            if (startDate)
                match.spentAt.$gte = new Date(startDate);
            if (endDate)
                match.spentAt.$lte = new Date(endDate);
        }
        let groupId;
        let sortId;
        if (period === 'daily') {
            groupId = { year: { $year: '$spentAt' }, month: { $month: '$spentAt' }, day: { $dayOfMonth: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.month': 1, '_id.day': 1 };
        }
        else if (period === 'weekly') {
            groupId = { year: { $year: '$spentAt' }, week: { $week: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.week': 1 };
        }
        else if (period === 'monthly') {
            groupId = { year: { $year: '$spentAt' }, month: { $month: '$spentAt' } };
            sortId = { '_id.year': 1, '_id.month': 1 };
        }
        else {
            // Yearly
            groupId = { year: { $year: '$spentAt' } };
            sortId = { '_id.year': 1 };
        }
        const stats = yield transaction_model_1.Transaction.aggregate([
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
            }
            else if (period === 'weekly') {
                label = `${s._id.year}-W${s._id.week}`;
            }
            else if (period === 'monthly') {
                label = `${s._id.year}-${String(s._id.month).padStart(2, '0')}`;
            }
            else {
                label = `${s._id.year}`;
            }
            return { label, spent: s.spent, budget: s.budget };
        });
        res.status(200).json(formatted);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getSpendingTrends = getSpendingTrends;
