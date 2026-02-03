"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loginSchema = void 0;
const zod_1 = require("zod");
exports.loginSchema = zod_1.z.object({
    identifier: zod_1.z.string().min(1, 'Identifier is required'), // Could be email or username
    password: zod_1.z.string().min(6, 'Password must be at least 6 characters long'),
});
