import { Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { Category } from '../models/category.model';
import { z } from 'zod';

const createCategorySchema = z.object({
    name: z.string(),
    parent: z.string().optional(),
    budget: z.number().min(0).optional(),
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
export const seedDefaults = async (userId: string) => {
    const existing = await Category.findOne({ userId });
    if (existing) return;

    // Create main categories
    const createdMain = await Promise.all(
        DEFAULT_CATEGORIES.map(cat =>
            Category.create({ userId, name: cat.name, budget: cat.budget, isDefault: true })
        )
    );

    // Find "Savings" and add sub-categories
    const savings = createdMain.find(c => c.name === 'Savings');
    if (savings) {
        await Promise.all(
            SAVINGS_SUB_CATEGORIES.map(sub =>
                Category.create({ userId, name: sub, parent: savings._id, isDefault: true })
            )
        );
    }
};

/**
 * Get Categories (Hierarchical breakdown)
 */
export const getCategories = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        // Ensure defaults exist
        await seedDefaults(userId!);

        const categories = await Category.find({ userId }).sort({ name: 1 });
        res.status(200).json(categories);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Create Category
 */
export const createCategory = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { name, parent, budget } = createCategorySchema.parse(req.body);

        const category = await Category.create({
            userId,
            name,
            parent,
            budget,
        });

        res.status(201).json(category);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Update Category (Budget or Name)
 */
export const updateCategory = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { id } = req.params;
        const { name, budget } = createCategorySchema.partial().parse(req.body);

        const category = await Category.findOneAndUpdate(
            { _id: id, userId },
            { name, budget },
            { new: true }
        );

        if (!category) return res.status(404).json({ message: 'Category not found' });

        res.status(200).json(category);
    } catch (error) {
        if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Delete Category
 */
export const deleteCategory = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const { id } = req.params;

        const result = await Category.findOneAndDelete({ _id: id, userId });
        if (!result) return res.status(404).json({ message: 'Category not found' });

        // Also delete or un-parent children? 
        // For simplicity, we just un-parent them
        await Category.updateMany({ parent: id }, { $unset: { parent: 1 } });

        res.status(200).json({ message: 'Category deleted' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
