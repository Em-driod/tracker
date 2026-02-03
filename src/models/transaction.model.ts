import { Schema, model, Document, Types } from 'mongoose';

export enum TransactionStatus {
    PLANNED = 'PLANNED',
    COMPLETED = 'COMPLETED'
}

export interface ITransaction extends Document {
    userId: Types.ObjectId;
    categoryId: Types.ObjectId; // Reference to Category model
    title: string;
    description?: string;
    budgetedAmount: number;
    actualAmount: number;
    status: TransactionStatus;
    spentAt: Date;
    createdAt: Date;
    updatedAt: Date;
}

const transactionSchema = new Schema<ITransaction>({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    categoryId: { type: Schema.Types.ObjectId, ref: 'Category', required: true },
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

export const Transaction = model<ITransaction>('Transaction', transactionSchema);
