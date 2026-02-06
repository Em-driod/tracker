"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logout = exports.changePassword = exports.toggleFingerprint = exports.changePin = exports.completeWebAuthnLogin = exports.initWebAuthnLogin = exports.completeWebAuthnRegistration = exports.initWebAuthnRegistration = exports.verifyLoginOtp = exports.verifyRegistrationOtp = exports.resetPassword = exports.verifyOtp = exports.forgotPassword = exports.login = exports.register = void 0;
const zod_1 = require("zod");
const password_1 = require("../utils/password");
const jwt_1 = require("../utils/jwt");
const email_1 = require("../services/email");
const otp_1 = require("../utils/otp");
const user_model_1 = require("../models/user.model");
const config_1 = require("../config");
const changePinSchema = zod_1.z.object({
    pin: zod_1.z.string().length(4, { message: "PIN must be 4 digits" }).regex(/^\d+$/, { message: "PIN must contain only numbers" }),
});
const changePasswordSchema = zod_1.z.object({
    oldPassword: zod_1.z.string(),
    newPassword: zod_1.z.string().min(8, { message: "Password must be at least 8 characters long" }),
});
// --- Validation Schemas ---
const registerSchema = zod_1.z.object({
    fullName: zod_1.z.string(),
    email: zod_1.z.string().email(),
    dateOfBirth: zod_1.z.string().refine((val) => !isNaN(Date.parse(val)), { message: "Invalid date format" }),
    password: zod_1.z.string().min(8, { message: "Password must be at least 8 characters long" }),
    mobile: zod_1.z.string().optional(),
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().optional(),
    identifier: zod_1.z.string().optional(),
    password: zod_1.z.string(),
}).refine(data => data.email || data.identifier, {
    message: "Either email or identifier is required",
    path: ["identifier"]
});
const forgotPasswordSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
});
const verifyOtpSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    otp: zod_1.z.string(),
});
const verifyRegistrationOtpSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    otp: zod_1.z.string(),
});
const resetPasswordSchema = zod_1.z.object({
    email: zod_1.z.string().email().optional(),
    otp: zod_1.z.string().optional(),
    resetToken: zod_1.z.string().optional(),
    newPassword: zod_1.z.string().min(8, { message: "Password must be at least 8 characters long" }),
}).refine(data => data.resetToken || (data.email && data.otp), {
    message: "Either resetToken or both email and otp are required",
});
const verifyLoginOtpSchema = zod_1.z.object({
    identifier: zod_1.z.string(),
    otp: zod_1.z.string(),
});
const initWebAuthnRegistrationSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
});
const completeWebAuthnRegistrationSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    credential: zod_1.z.object({
        id: zod_1.z.string(),
        rawId: zod_1.z.string(),
        response: zod_1.z.object({
            attestationObject: zod_1.z.string(),
            clientDataJSON: zod_1.z.string(),
        }),
        type: zod_1.z.string(),
        clientExtensionResults: zod_1.z.object({}).passthrough().optional(),
        transports: zod_1.z.array(zod_1.z.string()).optional(),
    }),
});
const initWebAuthnLoginSchema = zod_1.z.object({
    identifier: zod_1.z.string(),
});
const completeWebAuthnLoginSchema = zod_1.z.object({
    identifier: zod_1.z.string().optional(),
    credential: zod_1.z.object({
        id: zod_1.z.string(),
        rawId: zod_1.z.string(),
        response: zod_1.z.object({
            authenticatorData: zod_1.z.string(),
            clientDataJSON: zod_1.z.string(),
            signature: zod_1.z.string(),
            userHandle: zod_1.z.string().optional(),
        }),
        type: zod_1.z.string(),
        clientExtensionResults: zod_1.z.object({}).passthrough().optional(),
    }),
});
// --- Controller Functions ---
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { fullName, email, dateOfBirth: dobString, password, mobile } = registerSchema.parse(req.body);
        const passwordStrength = (0, password_1.checkPasswordStrength)(password);
        if (passwordStrength === 'weak') {
            return res.status(400).json({ message: 'Password is too weak. Please include uppercase, lowercase, numbers, and symbols.' });
        }
        const dateOfBirth = new Date(dobString);
        const age = new Date().getFullYear() - dateOfBirth.getFullYear();
        if (age < 13) {
            return res.status(400).json({ message: 'You must be at least 13 years old to register' });
        }
        // Generate username from email if not provided (e.g., john@doe.com -> john_doe_123)
        const username = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '_') + '_' + Math.floor(Math.random() * 1000);
        const existingUser = yield user_model_1.User.findOne({
            $or: [{ email }, { username }],
        });
        if (existingUser) {
            return res.status(400).json({ message: 'Email or username already exists' });
        }
        const hashedPassword = yield (0, password_1.hashPassword)(password);
        const newUser = new user_model_1.User({
            fullName,
            email,
            username,
            mobile,
            dateOfBirth,
            password: hashedPassword,
            isVerified: false, // Set isVerified to false initially
        });
        yield newUser.save();
        // Generate and send OTP for registration verification
        const otp = (0, otp_1.generateOtp)();
        const hashedOtp = yield (0, password_1.hashPassword)(otp);
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes
        const otpDoc = yield user_model_1.Otp.create({ userId: newUser._id, code: hashedOtp, expiresAt, type: 'REGISTER' });
        yield (0, email_1.sendEmail)(email, 'Verify Your Account - OTP', `Your OTP for account verification is: ${otp}`);
        res.status(200).json({ message: 'Registration successful! Please verify your email with the OTP sent to your inbox.' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.register = register;
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, identifier: bodyIdentifier, password } = loginSchema.parse(req.body);
        const identifier = bodyIdentifier || email;
        const user = yield user_model_1.User.findOne({
            $or: [{ email: identifier }, { username: identifier }],
        });
        if (!user || !user.password) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isPasswordValid = yield (0, password_1.comparePassword)(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        if (!user.isVerified) {
            return res.status(401).json({ message: 'Please verify your email to log in.' });
        }
        // Check for inactivity (2 weeks = 14 days * 24 hours * 60 minutes * 60 seconds * 1000 milliseconds)
        const twoWeeksAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
        const isInactive = !user.lastActivityAt || user.lastActivityAt < twoWeeksAgo;
        if (isInactive) {
            const otp = (0, otp_1.generateOtp)();
            const hashedOtp = yield (0, password_1.hashPassword)(otp);
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes
            // Store OTP for login re-verification
            yield user_model_1.Otp.findOneAndUpdate({ userId: user._id, type: 'LOGIN' }, { code: hashedOtp, expiresAt, type: 'LOGIN' }, { upsert: true, new: true });
            yield (0, email_1.sendEmail)(user.email, 'Login Verification OTP', `Your OTP for login verification is: ${otp}`);
            return res.status(202).json({ message: 'Account inactive. An OTP has been sent to your email for login verification.' });
        }
        // If active, proceed with normal login
        user.lastActivityAt = new Date();
        yield user.save();
        const token = (0, jwt_1.generateToken)({ userId: user._id.toString() }, '1h');
        res.status(200).json({
            message: 'Login successful',
            token
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.login = login;
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = forgotPasswordSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.json({ message: 'If a user with that email exists, an OTP has been sent.' });
        }
        const otp = (0, otp_1.generateOtp)();
        const hashedOtp = yield (0, password_1.hashPassword)(otp);
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        // Save/Update OTP in the Otp collection
        yield user_model_1.Otp.findOneAndUpdate({ userId: user._id, type: 'RESET' }, { code: hashedOtp, expiresAt, type: 'RESET' }, { upsert: true, new: true });
        yield (0, email_1.sendEmail)(email, 'Your Password Reset OTP', `Your OTP is: ${otp}`);
        res.json({ message: 'If a user with that email exists, an OTP has been sent.' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.forgotPassword = forgotPassword;
const verifyOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, otp } = verifyOtpSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }
        const otpRecord = yield user_model_1.Otp.findOne({ userId: user._id, type: 'RESET' });
        if (!otpRecord) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }
        if (new Date() > otpRecord.expiresAt) {
            return res.status(400).json({ message: 'OTP has expired' });
        }
        const isOtpValid = yield (0, password_1.comparePassword)(otp, otpRecord.code);
        if (!isOtpValid)
            return res.status(400).json({ message: 'Invalid OTP' });
        // Cleanup
        yield user_model_1.Otp.deleteOne({ _id: otpRecord._id });
        const resetToken = (0, jwt_1.generateToken)({ userId: user._id.toString() }, '15m');
        res.json({ resetToken });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.verifyOtp = verifyOtp;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { resetToken, email, otp, newPassword } = resetPasswordSchema.parse(req.body);
        const passwordStrength = (0, password_1.checkPasswordStrength)(newPassword);
        if (passwordStrength === 'weak') {
            return res.status(400).json({ message: 'Password is too weak. Please include uppercase, lowercase, numbers, and symbols.' });
        }
        let userId;
        if (resetToken) {
            const decoded = (0, jwt_1.verifyToken)(resetToken);
            if (!decoded)
                return res.status(400).json({ message: 'Invalid or expired reset token' });
            userId = decoded.userId;
        }
        else if (email && otp) {
            const user = yield user_model_1.User.findOne({ email });
            if (!user)
                return res.status(400).json({ message: 'Invalid OTP or email' });
            const otpRecord = yield user_model_1.Otp.findOne({ userId: user._id, type: 'RESET' });
            if (!otpRecord || new Date() > otpRecord.expiresAt) {
                return res.status(400).json({ message: 'Invalid or expired OTP' });
            }
            const isOtpValid = yield (0, password_1.comparePassword)(otp, otpRecord.code);
            if (!isOtpValid)
                return res.status(400).json({ message: 'Invalid OTP' });
            userId = user._id.toString();
            yield user_model_1.Otp.deleteOne({ _id: otpRecord._id });
        }
        else {
            return res.status(400).json({ message: 'Insufficient data for password reset' });
        }
        const hashedPassword = yield (0, password_1.hashPassword)(newPassword);
        yield user_model_1.User.findByIdAndUpdate(userId, { password: hashedPassword });
        res.json({ message: 'Password has been reset successfully' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.resetPassword = resetPassword;
const verifyRegistrationOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, otp } = verifyRegistrationOtpSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid OTP or user not found' });
        }
        const otpRecord = yield user_model_1.Otp.findOne({ userId: user._id, type: 'REGISTER' });
        if (!otpRecord) {
            return res.status(400).json({ message: 'Invalid OTP or user not found' });
        }
        if (new Date() > otpRecord.expiresAt) {
            return res.status(400).json({ message: 'OTP has expired' });
        }
        const isOtpValid = yield (0, password_1.comparePassword)(otp, otpRecord.code);
        if (!isOtpValid)
            return res.status(400).json({ message: 'Invalid OTP' });
        // Mark user as verified
        user.isVerified = true;
        yield user.save();
        // Cleanup OTP
        yield user_model_1.Otp.deleteOne({ _id: otpRecord._id });
        res.status(200).json({ message: 'Email verified successfully! You can now log in.' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.verifyRegistrationOtp = verifyRegistrationOtp;
const verifyLoginOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { identifier, otp } = verifyLoginOtpSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) {
            return res.status(400).json({ message: 'Invalid OTP or user not found' });
        }
        const otpRecord = yield user_model_1.Otp.findOne({ userId: user._id, type: 'LOGIN' });
        if (!otpRecord) {
            return res.status(400).json({ message: 'Invalid OTP or user not found' });
        }
        if (new Date() > otpRecord.expiresAt) {
            return res.status(400).json({ message: 'OTP has expired' });
        }
        const isOtpValid = yield (0, password_1.comparePassword)(otp, otpRecord.code);
        if (!isOtpValid)
            return res.status(400).json({ message: 'Invalid OTP' });
        // Cleanup OTP
        yield user_model_1.Otp.deleteOne({ _id: otpRecord._id });
        user.lastActivityAt = new Date(); // Update last activity on successful OTP login
        yield user.save();
        const token = (0, jwt_1.generateToken)({ userId: user._id.toString() }, '1h');
        res.status(200).json({ message: 'Login successful', token });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.verifyLoginOtp = verifyLoginOtp;
const initWebAuthnRegistration = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = initWebAuthnRegistrationSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const authenticatorSelection = {
            authenticatorAttachment: 'cross-platform', // Can be 'platform' or 'cross-platform'
            userVerification: 'preferred', // 'required', 'preferred', or 'discouraged'
            residentKey: 'preferred', // 'required', 'preferred', or 'discouraged' (for discoverable credentials/passkeys)
        };
        const attestationOptions = yield config_1.config.webauthn.fido2.attestationOptions({
            user: {
                id: user._id.toString(),
                name: user.email,
                displayName: user.fullName,
            },
            authenticatorSelection: authenticatorSelection,
        });
        // Store the challenge for verification in the next step
        user.currentWebAuthnChallenge = Buffer.from(attestationOptions.challenge).toString('base64url');
        yield user.save();
        res.status(200).json(attestationOptions);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.initWebAuthnRegistration = initWebAuthnRegistration;
const completeWebAuthnRegistration = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, credential } = completeWebAuthnRegistrationSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (!user.currentWebAuthnChallenge) {
            return res.status(400).json({ message: 'No WebAuthn registration in progress for this user.' });
        }
        const attestationExpectations = {
            challenge: user.currentWebAuthnChallenge,
            origin: config_1.config.webauthn.origin,
            factor: 'either',
        };
        // Convert string fields to Buffer as required by fido2-lib
        const convertedAttestationResponse = Object.assign(Object.assign({}, credential), { id: Buffer.from(credential.id, 'base64url'), rawId: Buffer.from(credential.rawId, 'base64url'), response: {
                attestationObject: Buffer.from(credential.response.attestationObject, 'base64url'),
                clientDataJSON: Buffer.from(credential.response.clientDataJSON, 'base64url'),
            } });
        const attestationResult = yield config_1.config.webauthn.fido2.attestationResult(convertedAttestationResponse, attestationExpectations);
        const { credId, publicKey, counter, credType, aaguid, fmt, attestationCert, userHandle, transports, } = attestationResult.authnrData;
        const newCredential = {
            credID: Buffer.from(credId),
            publicKey: Buffer.from(publicKey),
            counter: counter,
            credType: credType,
            transports: transports,
            aaguid: Buffer.from(aaguid),
            fmt: fmt,
            attestationCert: attestationCert ? Buffer.from(attestationCert) : undefined,
            userHandle: userHandle ? Buffer.from(userHandle) : undefined,
        };
        if (!user.webauthn_credentials) {
            user.webauthn_credentials = [];
        }
        user.webauthn_credentials.push(newCredential);
        user.currentWebAuthnChallenge = undefined; // Clear the challenge after use
        yield user.save();
        res.status(200).json({ message: 'WebAuthn registration successful!' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.completeWebAuthnRegistration = completeWebAuthnRegistration;
const initWebAuthnLogin = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { identifier } = initWebAuthnLoginSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (!user.webauthn_credentials || user.webauthn_credentials.length === 0) {
            return res.status(400).json({ message: 'No WebAuthn credentials registered for this user.' });
        }
        const allowCredentials = user.webauthn_credentials.map(cred => ({
            id: cred.credID,
            type: 'public-key',
            transports: cred.transports,
        }));
        const assertionOptions = yield config_1.config.webauthn.fido2.assertionOptions({
            allowCredentials: allowCredentials,
            userVerification: 'preferred',
            rpId: config_1.config.webauthn.rpId,
            timeout: 60000, // Example timeout, should be configurable
        });
        user.currentWebAuthnChallenge = Buffer.from(assertionOptions.challenge).toString('base64url');
        yield user.save();
        res.status(200).json(assertionOptions);
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.initWebAuthnLogin = initWebAuthnLogin;
const completeWebAuthnLogin = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const { identifier: bodyIdentifier, credential } = completeWebAuthnLoginSchema.parse(req.body);
        const identifier = bodyIdentifier || ((_a = req.user) === null || _a === void 0 ? void 0 : _a.email); // Fallback if needed, though login usually has it
        const user = yield user_model_1.User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (!user.currentWebAuthnChallenge) {
            return res.status(400).json({ message: 'No WebAuthn login in progress for this user.' });
        }
        if (!user.webauthn_credentials || user.webauthn_credentials.length === 0) {
            return res.status(400).json({ message: 'No WebAuthn credentials registered for this user.' });
        }
        // Find the credential used for this assertion
        const authenticator = user.webauthn_credentials.find((cred) => cred.credID.toString('base64url') === credential.rawId);
        if (!authenticator) {
            return res.status(400).json({ message: 'Authenticator not found for this user.' });
        }
        const assertionExpectations = {
            challenge: user.currentWebAuthnChallenge,
            origin: config_1.config.webauthn.origin,
            publicKey: authenticator.publicKey.toString('base64url'),
            prevCounter: authenticator.counter,
            userHandle: Buffer.from(user._id.toString()).toString('base64url'),
            factor: 'either',
        };
        const convertedAssertionResponse = Object.assign(Object.assign({}, credential), { id: Buffer.from(credential.id, 'base64url'), rawId: Buffer.from(credential.rawId, 'base64url'), response: {
                authenticatorData: Buffer.from(credential.response.authenticatorData, 'base64url'),
                clientDataJSON: Buffer.from(credential.response.clientDataJSON, 'base64url'),
                signature: Buffer.from(credential.response.signature, 'base64url'),
                userHandle: credential.response.userHandle ? Buffer.from(credential.response.userHandle, 'base64url') : undefined,
            } });
        const assertionResult = yield config_1.config.webauthn.fido2.assertionResult(convertedAssertionResponse, assertionExpectations);
        // Update the counter
        authenticator.counter = assertionResult.authnrData.counter;
        user.currentWebAuthnChallenge = undefined; // Clear the challenge
        user.lastActivityAt = new Date(); // Update last activity on successful login
        yield user.save();
        const token = (0, jwt_1.generateToken)({ userId: user._id.toString() }, '1h');
        res.status(200).json({ message: 'WebAuthn login successful!', token });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.completeWebAuthnLogin = completeWebAuthnLogin;
const changePin = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { pin } = changePinSchema.parse(req.body);
        const hashedPin = yield (0, password_1.hashPassword)(pin);
        yield user_model_1.User.findByIdAndUpdate(userId, { pin: hashedPin });
        res.status(200).json({ message: 'PIN updated successfully' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.changePin = changePin;
const toggleFingerprint = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { enabled } = req.body;
        yield user_model_1.User.findByIdAndUpdate(userId, { isFingerprintEnabled: !!enabled });
        res.status(200).json({ message: `Fingerprint ${enabled ? 'enabled' : 'disabled'} successfully` });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.toggleFingerprint = toggleFingerprint;
const changePassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const { oldPassword, newPassword } = changePasswordSchema.parse(req.body);
        const user = yield user_model_1.User.findById(userId);
        if (!user || !user.password) {
            return res.status(404).json({ message: 'User not found' });
        }
        const isPasswordValid = yield (0, password_1.comparePassword)(oldPassword, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid old password' });
        }
        const passwordStrength = (0, password_1.checkPasswordStrength)(newPassword);
        if (passwordStrength === 'weak') {
            return res.status(400).json({ message: 'New password is too weak.' });
        }
        const hashedNewPassword = yield (0, password_1.hashPassword)(newPassword);
        user.password = hashedNewPassword;
        yield user.save();
        res.status(200).json({ message: 'Password updated successfully' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.changePassword = changePassword;
const logout = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    // In a JWT setup without blacklisting, logout is usually handled on the client side by deleting the token.
    // We can return a success message here.
    res.status(200).json({ message: 'Logout successful' });
});
exports.logout = logout;
