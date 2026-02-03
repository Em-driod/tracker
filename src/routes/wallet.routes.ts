import { Router } from 'express';
import * as walletController from '../controllers/wallet.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

router.get('/', authenticate, walletController.getWallet);
router.post('/fund', authenticate, walletController.initiateFunding);
router.post('/withdraw', authenticate, walletController.withdraw);
router.post('/webhook', walletController.handleWebhook); // Paystack webhook is public (verification inside)

export default router;
