"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticate = void 0;
const jwt_1 = require("../utils/jwt");
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header missing' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token missing' });
    }
    const decoded = (0, jwt_1.verifyToken)(token);
    if (!decoded) {
        return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = decoded;
    next();
};
exports.authenticate = authenticate;
