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
exports.getTermsAndConditions = exports.deleteAccount = exports.updateSettings = exports.updateProfile = exports.getProfile = void 0;
const user_model_1 = require("../models/user.model");
const zod_1 = require("zod");
const updateProfileSchema = zod_1.z.object({
    fullName: zod_1.z.string().optional(),
    username: zod_1.z.string().optional(),
    mobile: zod_1.z.string().optional(),
    email: zod_1.z.string().email().optional(),
    profileImage: zod_1.z.string().optional(), // Base64 or URL
    identificationImage: zod_1.z.string().optional(),
});
const updateSettingsSchema = zod_1.z.object({
    pushEnabled: zod_1.z.boolean().optional(),
    emailEnabled: zod_1.z.boolean().optional(),
});
const getProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const user = yield user_model_1.User.findById(userId).select('-password -pin -webauthn_credentials -currentWebAuthnChallenge');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.getProfile = getProfile;
const updateProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const updates = updateProfileSchema.parse(req.body);
        if (updates.username) {
            const existingUser = yield user_model_1.User.findOne({ username: updates.username, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({ message: 'Username already taken' });
            }
        }
        if (updates.email) {
            const existingUser = yield user_model_1.User.findOne({ email: updates.email, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already in use' });
            }
        }
        const user = yield user_model_1.User.findByIdAndUpdate(userId, { $set: updates }, { new: true }).select('-password -pin');
        res.status(200).json({ message: 'Profile updated successfully', user });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.updateProfile = updateProfile;
const updateSettings = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        const settings = updateSettingsSchema.parse(req.body);
        const updateFields = {};
        if (settings.pushEnabled !== undefined)
            updateFields['notificationSettings.pushEnabled'] = settings.pushEnabled;
        if (settings.emailEnabled !== undefined)
            updateFields['notificationSettings.emailEnabled'] = settings.emailEnabled;
        yield user_model_1.User.findByIdAndUpdate(userId, { $set: updateFields });
        res.status(200).json({ message: 'Settings updated successfully' });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({ message: error.issues });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.updateSettings = updateSettings;
const deleteAccount = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId;
        yield user_model_1.User.findByIdAndDelete(userId);
        // Note: In a real app, you might want to delete related data (transactions, wallets, etc.)
        res.status(200).json({ message: 'Account deleted successfully' });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.deleteAccount = deleteAccount;
const getTermsAndConditions = (req, res) => {
    res.status(200).json({
        title: 'Terms and Conditions',
        content: 'Standard terms and conditions for using the Tracker application. By using this app, you agree to our data processing policies...',
        updatedAt: new Date().toISOString(),
    });
};
exports.getTermsAndConditions = getTermsAndConditions;
