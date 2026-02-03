import { Router } from 'express';
import * as authController from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-otp', authController.verifyOtp);
router.post('/verify-registration-otp', authController.verifyRegistrationOtp);
router.post('/verify-login-otp', authController.verifyLoginOtp);
router.post('/reset-password', authController.resetPassword);

router.post('/webauthn/register/init', authController.initWebAuthnRegistration);
router.post('/webauthn/register/complete', authController.completeWebAuthnRegistration);
router.post('/webauthn/login/init', authController.initWebAuthnLogin);
router.post('/webauthn/login/complete', authController.completeWebAuthnLogin);

export default router;
