import { Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { Notification } from '../models/notification.model';
import { z } from 'zod';

export const getNotifications = async (req: CustomRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        const notifications = await Notification.find({ userId }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const markAsRead = async (req: CustomRequest, res: Response) => {
    try {
        const { id } = req.params;
        const userId = req.user?.userId;

        const notification = await Notification.findOneAndUpdate(
            { _id: id, userId },
            { isRead: true },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ message: 'Notification not found' });
        }

        res.status(200).json({ message: 'Notification marked as read', notification });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
