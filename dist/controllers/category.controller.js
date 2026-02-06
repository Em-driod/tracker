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
exports.deleteCategory = exports.updateCategory = exports.createCategory = exports.getCategories = exports.seedDefaults = void 0;
const category_model_1 = require("../models/category.model");
const zod_1 = require("zod");
const createCategorySchema = zod_1.z.object({
    name: zod_1.z.string(),
    parent: zod_1.z.string().optional(),
    budget: zod_1.z.number().min(0).optional(),
});
const DEFAULT_CATEGORIES = [
    { name: 'Food', budget: 0 },
    { name: 'Transport', budget: 0 },
    { name: 'Medicine', budget: 0 },
    { name: 'Groceries', budget: 0 },
    { name: 'Rent', budget: 0 },
    { name: 'Gifts', budget: 0 },
    { name: 'Savings', budget: 0 },
    { name: 'Entertainment', budget: 0 },
];
const SAVINGS_SUB_CATEGORIES = [
    'Travel', 'New Housing', 'Car', 'Wedding'
];
/**
 * Seed Default Categories for a User
 */
const seedDefaults = (userId) => __awaiter(void 0, void 0, void 0, function* () {
    const existing = yield category_model_1.Category.findOne({ userId });
    if (existing)
        return;
    // Create main categories
    const createdMain = yield Promise.all(DEFAULT_CATEGORIES.map(cat => category_model_1.Category.create({ userId, name: cat.name, budget: cat.budget, isDefault: true })));
    // Find "Savings" and add sub-categories
    const savings = createdMain.find(c => c.name === 'Savings');
    if (savings) {
        yield Promise.all(SAVINGS_SUB_CATEGORIES.map(sub => category_model_1.Category.create({ userId, name: sub, parent: savings._id, isDefault: true })));
    }
});
exports.seedDefaults = seedDefaults;
/**
 * Get Categories (Hierarchical breakdown)
 */
const getCategories = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        // Ensure defaults exist
        yield (0, exports.seedDefaults)(userId);
        const categories = yield category_model_1.Category.find({ userId }).sort({ name: 1 });
        res.status(200).json(categories);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getCategories = getCategories;
/**
 * Create Category
 */
const createCategory = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { name, parent, budget } = createCategorySchema.parse(req.body);
        const category = yield category_model_1.Category.create({
            userId,
            name,
            parent,
            budget,
        });
        res.status(201).json(category);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.createCategory = createCategory;
/**
 * Update Category (Budget or Name)
 */
const updateCategory = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { id } = req.params;
        const { name, budget } = createCategorySchema.partial().parse(req.body);
        const category = yield category_model_1.Category.findOneAndUpdate({ _id: id, userId }, { name, budget }, { new: true });
        if (!category)
            return res.status(404).json({ message: 'Category not found' });
        res.status(200).json(category);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.updateCategory = updateCategory;
/**
 * Delete Category
 */
const deleteCategory = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { id } = req.params;
        const result = yield category_model_1.Category.findOneAndDelete({ _id: id, userId });
        if (!result)
            return res.status(404).json({ message: 'Category not found' });
        // Also delete or un-parent children? 
        // For simplicity, we just un-parent them
        yield category_model_1.Category.updateMany({ parent: id }, { $unset: { parent: 1 } });
        res.status(200).json({ message: 'Category deleted' });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.deleteCategory = deleteCategory;
