"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const webauthn_1 = require("./webauthn");
dotenv_1.default.config();
exports.config = {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    email: {
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    webauthn: {
        fido2: webauthn_1.fido2,
        rpId: webauthn_1.rpId,
        rpName: webauthn_1.rpName,
        origin: webauthn_1.origin,
    },
    paystack: {
        secretKey: process.env.PAYSTACK_SECRET_KEY,
    },
};
