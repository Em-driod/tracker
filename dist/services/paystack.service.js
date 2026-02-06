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
exports.verifyTransaction = exports.initializeTransaction = void 0;
const config_1 = require("../config");
const PAYSTACK_API_URL = 'https://api.paystack.co';
const initializeTransaction = (email, amount) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield fetch(`${PAYSTACK_API_URL}/transaction/initialize`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${config_1.config.paystack.secretKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email,
            amount: amount * 100, // Paystack amount is in kobo (NGN) or cents
            callback_url: `${config_1.config.webauthn.origin}/dashboard/wallet`, // Fallback to origin
        }),
    });
    const data = yield response.json();
    if (!data.status) {
        throw new Error(data.message || 'Paystack initialization failed');
    }
    return data.data; // { authorization_url, access_code, reference }
});
exports.initializeTransaction = initializeTransaction;
const verifyTransaction = (reference) => __awaiter(void 0, void 0, void 0, function* () {
    const response = yield fetch(`${PAYSTACK_API_URL}/transaction/verify/${reference}`, {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${config_1.config.paystack.secretKey}`,
        },
    });
    const data = yield response.json();
    if (!data.status) {
        throw new Error(data.message || 'Paystack verification failed');
    }
    return data.data; // Includes amount, status, metadata, etc.
});
exports.verifyTransaction = verifyTransaction;
