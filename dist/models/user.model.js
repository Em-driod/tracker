"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.User = exports.Otp = void 0;
const mongoose_1 = require("mongoose");
// OTP Schema
const otpSchema = new mongoose_1.Schema({
    userId: { type: mongoose_1.Schema.Types.ObjectId, required: true, ref: 'User' },
    code: { type: String, required: true },
    expiresAt: { type: Date, required: true },
});
exports.Otp = (0, mongoose_1.model)('Otp', otpSchema);
// User Schema
const userSchema = new mongoose_1.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    dob: { type: Date, required: true },
    password: { type: String, required: false },
    biometric_enabled: { type: Boolean, default: false },
});
exports.User = (0, mongoose_1.model)('User', userSchema);
