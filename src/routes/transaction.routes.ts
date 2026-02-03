import { Router } from 'express';
import * as transactionController from '../controllers/transaction.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

router.post('/', authenticate, transactionController.createTransaction);
router.get('/', authenticate, transactionController.getTransactions);
router.post('/:id/complete', authenticate, transactionController.completeTransaction);
router.delete('/:id', authenticate, transactionController.deleteTransaction);

export default router;
