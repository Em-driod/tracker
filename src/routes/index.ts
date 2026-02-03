import { Router } from 'express';
import authRoutes from './auth.routes';
import walletRoutes from './wallet.routes';
import transactionRoutes from './transaction.routes';
import analyticsRoutes from './analytics.routes';
import categoryRoutes from './category.routes';

const router = Router();

router.use('/auth', authRoutes);
router.use('/wallet', walletRoutes);
router.use('/transactions', transactionRoutes);
router.use('/analytics', analyticsRoutes);
router.use('/categories', categoryRoutes);

export default router;
