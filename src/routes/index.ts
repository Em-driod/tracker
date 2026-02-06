import { Router } from 'express';
import authRoutes from './auth.routes';
import walletRoutes from './wallet.routes';
import transactionRoutes from './transaction.routes';
import analyticsRoutes from './analytics.routes';
import categoryRoutes from './category.routes';
import userRoutes from './user.routes';
import notificationRoutes from './notification.routes';

const router = Router();

router.use('/auth', authRoutes);
router.use('/wallet', walletRoutes);
router.use('/transactions', transactionRoutes);
router.use('/analytics', analyticsRoutes);
router.use('/categories', categoryRoutes);
router.use('/user', userRoutes);
router.use('/notifications', notificationRoutes);

export default router;
