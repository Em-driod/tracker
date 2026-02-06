import { Request, Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { User } from '../models/user.model';
import { z } from 'zod';

const updateProfileSchema = z.object({
    fullName: z.string().optional(),
    username: z.string().optional(),
    mobile: z.string().optional(),
    email: z.string().email().optional(),
    profileImage: z.string().optional(), // Base64 or URL
    identificationImage: z.string().optional(),
});

const updateSettingsSchema = z.object({
    pushEnabled: z.boolean().optional(),
    emailEnabled: z.boolean().optional(),
});

export const getProfile = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const user = await User.findById(userId).select('-password -pin -webauthn_credentials -currentWebAuthnChallenge');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const updateProfile = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const updates = updateProfileSchema.parse(req.body);

        if (updates.username) {
            const existingUser = await User.findOne({ username: updates.username, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({ message: 'Username already taken' });
            }
        }

        if (updates.email) {
            const existingUser = await User.findOne({ email: updates.email, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already in use' });
            }
        }

        const user = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true }).select('-password -pin');

        res.status(200).json({ message: 'Profile updated successfully', user });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const updateSettings = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const settings = updateSettingsSchema.parse(req.body);

        const updateFields: any = {};
        if (settings.pushEnabled !== undefined) updateFields['notificationSettings.pushEnabled'] = settings.pushEnabled;
        if (settings.emailEnabled !== undefined) updateFields['notificationSettings.emailEnabled'] = settings.emailEnabled;

        await User.findByIdAndUpdate(userId, { $set: updateFields });

        res.status(200).json({ message: 'Settings updated successfully' });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const deleteAccount = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        await User.findByIdAndDelete(userId);
        // Note: In a real app, you might want to delete related data (transactions, wallets, etc.)
        res.status(200).json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getTermsAndConditions = (req: Request, res: Response) => {
    res.status(200).json({
        title: 'Terms and Conditions',
        content: 'Standard terms and conditions for using the Tracker application. By using this app, you agree to our data processing policies...',
        updatedAt: new Date().toISOString(),
    });
};
