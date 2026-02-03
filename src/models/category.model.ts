import { Schema, model, Document, Types } from 'mongoose';

export interface ICategory extends Document {
    userId?: Types.ObjectId; // Optional: Global categories have no userId
    name: string;
    parent?: Types.ObjectId;
    budget: number;
    icon?: string;
    color?: string;
    isDefault: boolean;
    createdAt: Date;
    updatedAt: Date;
}

const categorySchema = new Schema<ICategory>({
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    parent: { type: Schema.Types.ObjectId, ref: 'Category' },
    budget: { type: Number, default: 0 },
    icon: { type: String },
    color: { type: String },
    isDefault: { type: Boolean, default: false },
}, { timestamps: true });

// Ensure a user can't have duplicate categories with the same name and parent
categorySchema.index({ userId: 1, name: 1, parent: 1 }, { unique: true });

export const Category = model<ICategory>('Category', categorySchema);
