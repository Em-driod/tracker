import { Router } from 'express';
import { authenticate } from '../middleware/auth';
import { getProfile, updateProfile, updateSettings, deleteAccount, getTermsAndConditions } from '../controllers/user.controller';

const router = Router();

router.get('/profile', authenticate, getProfile);
router.put('/profile', authenticate, updateProfile);
router.put('/settings', authenticate, updateSettings);
router.delete('/account', authenticate, deleteAccount);
router.get('/terms-and-conditions', getTermsAndConditions);

export default router;
