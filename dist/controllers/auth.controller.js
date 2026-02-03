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
exports.biometricLogin = exports.biometricSetup = exports.resetPassword = exports.verifyOtp = exports.forgotPassword = exports.login = exports.register = void 0;
const zod_1 = require("zod");
const password_1 = require("../utils/password");
const jwt_1 = require("../utils/jwt");
const email_1 = require("../services/email");
const otp_1 = require("../utils/otp");
const user_model_1 = require("../models/user.model");
// --- Validation Schemas ---
const registerSchema = zod_1.z.object({
    fullName: zod_1.z.string(),
    email: zod_1.z.string().email(),
    dob: zod_1.z.string().refine((val) => !isNaN(Date.parse(val)), { message: "Invalid date format" }),
    password: zod_1.z.string().min(8, { message: "Password must be at least 8 characters long" }),
    username: zod_1.z.string(),
});
const loginSchema = zod_1.z.object({
    identifier: zod_1.z.string(),
    password: zod_1.z.string(),
});
const forgotPasswordSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
});
const verifyOtpSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    otp: zod_1.z.string(),
});
const resetPasswordSchema = zod_1.z.object({
    resetToken: zod_1.z.string(),
    newPassword: zod_1.z.string().min(8, { message: "Password must be at least 8 characters long" }),
});
const biometricLoginSchema = zod_1.z.object({
    identifier: zod_1.z.string(),
});
// --- Controller Functions ---
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { fullName, email, dob, password, username } = registerSchema.parse(req.body);
        const dateOfBirth = new Date(dob);
        const age = new Date().getFullYear() - dateOfBirth.getFullYear();
        if (age < 13) {
            return res.status(400).json({ message: 'You must be at least 13 years old to register' });
        }
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
            dob: dateOfBirth,
            password: hashedPassword,
        });
        yield newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
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
        const { identifier, password } = loginSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({
            $or: [{ email: identifier }, { username: identifier }],
        });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isPasswordValid = yield (0, password_1.comparePassword)(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = (0, jwt_1.generateToken)({ userId: user._id.toString() });
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
        // TODO: Implement database query to find a user by email
        // TODO: Implement database query to find a user by email
        const user = yield user_model_1.User.findOne({ email });
        if (!user) {
            return res.json({ message: 'If a user with that email exists, an OTP has been sent.' });
        }
        const otp = (0, otp_1.generateOtp)();
        const hashedOtp = yield (0, password_1.hashPassword)(otp);
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        yield user_model_1.Otp.findOneAndUpdate({ userId: user._id }, { code: hashedOtp, expiresAt }, { upsert: true, new: true });
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
        const user = yield user_model_1.User.findOne({ email }).populate('otp');
        if (!user || !user.otp)
            return res.status(400).json({ message: 'Invalid OTP' });
        if (new Date() > user.otp.expiresAt)
            return res.status(400).json({ message: 'OTP has expired' });
        const isOtpValid = yield (0, password_1.comparePassword)(otp, user.otp.code);
        if (!isOtpValid)
            return res.status(400).json({ message: 'Invalid OTP' });
        yield user_model_1.Otp.deleteOne({ _id: user.otp._id });
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
        const { resetToken, newPassword } = resetPasswordSchema.parse(req.body);
        const decoded = (0, jwt_1.verifyToken)(resetToken);
        if (!decoded)
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        const hashedPassword = yield (0, password_1.hashPassword)(newPassword);
        yield user_model_1.User.findByIdAndUpdate(decoded.userId, { password: hashedPassword });
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
const biometricSetup = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        if (!userId)
            return res.status(401).json({ message: 'Authentication error' });
        // TODO: Implement database update for biometric_enabled status
        // await db.user.update({
        //   where: { id: userId },
        //   data: { biometric_enabled: true },
        // });
        yield user_model_1.User.findByIdAndUpdate(userId, { biometric_enabled: true });
        res.json({ message: 'Biometric authentication enabled successfully' });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.biometricSetup = biometricSetup;
const biometricLogin = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { identifier } = biometricLoginSchema.parse(req.body);
        const user = yield user_model_1.User.findOne({
            $or: [{ email: identifier }, { username: identifier }],
        });
        if (!user || !user.biometric_enabled) {
            return res.status(403).json({ message: 'Biometric login not available' });
        }
        const token = (0, jwt_1.generateToken)({ userId: user._id.toString() });
        res.json({ token });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError)
            return res.status(400).json({ message: error.issues });
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.biometricLogin = biometricLogin;
