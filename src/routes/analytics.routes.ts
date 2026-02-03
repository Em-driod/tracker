import { Router } from 'express';
import * as analyticsController from '../controllers/analytics.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

router.get('/bar-chart', authenticate, analyticsController.getBudgetVsSpent);
router.get('/category-summary', authenticate, analyticsController.getCategorySummary);
router.get('/spending-trends', authenticate, analyticsController.getSpendingTrends);

export default router;
