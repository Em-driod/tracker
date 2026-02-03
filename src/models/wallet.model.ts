import { Schema, model, Document, Types } from 'mongoose';

export interface IWalletOperation {
    type: 'DEPOSIT' | 'WITHDRAWAL' | 'SPEND';
    amount: number;
    description: string;
    reference?: string; // e.g., Paystack reference or Transaction ID
    date: Date;
}

export interface IWallet extends Document {
    userId: Types.ObjectId;
    balance: number;
    currency: string;
    history: IWalletOperation[];
    createdAt: Date;
    updatedAt: Date;
}

const walletOperationSchema = new Schema<IWalletOperation>({
    type: { type: String, required: true, enum: ['DEPOSIT', 'WITHDRAWAL', 'SPEND'] },
    amount: { type: Number, required: true },
    description: { type: String, required: true },
    reference: { type: String },
    date: { type: Date, default: Date.now },
});

const walletSchema = new Schema<IWallet>({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    balance: { type: Number, default: 0 },
    currency: { type: String, default: 'NGN' },
    history: [walletOperationSchema],
}, { timestamps: true });

export const Wallet = model<IWallet>('Wallet', walletSchema);
