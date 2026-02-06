"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.User = exports.Otp = void 0;
const mongoose_1 = require("mongoose");
const otpSchema = new mongoose_1.Schema({
    userId: { type: mongoose_1.Schema.Types.ObjectId, required: true, ref: 'User' },
    code: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    type: { type: String, required: true, enum: ['REGISTER', 'LOGIN', 'RESET'] },
});
exports.Otp = (0, mongoose_1.model)('Otp', otpSchema);
/**
 * User Schema
 */
const userSchema = new mongoose_1.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    mobile: { type: String, required: false },
    dateOfBirth: { type: Date, required: true },
    password: { type: String, required: false },
    isVerified: { type: Boolean, default: false },
    lastActivityAt: { type: Date, default: Date.now },
    webauthn_credentials: [{
            credID: { type: Buffer, required: true },
            publicKey: { type: Buffer, required: true },
            counter: { type: Number, required: true, default: 0 },
            credType: { type: String, required: true },
            transports: [{ type: String }],
            aaguid: { type: Buffer, required: true },
            fmt: { type: String, required: true },
            attestationCert: { type: Buffer },
            userHandle: { type: Buffer },
        }],
    currentWebAuthnChallenge: { type: String },
    profileImage: { type: String },
    pin: { type: String },
    isFingerprintEnabled: { type: Boolean, default: false },
    notificationSettings: {
        pushEnabled: { type: Boolean, default: true },
        emailEnabled: { type: Boolean, default: true },
    },
    identificationImage: { type: String },
});
exports.User = (0, mongoose_1.model)('User', userSchema);
