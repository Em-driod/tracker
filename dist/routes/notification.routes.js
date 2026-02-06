"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const notification_controller_1 = require("../controllers/notification.controller");
const router = (0, express_1.Router)();
router.get('/', auth_1.authenticate, notification_controller_1.getNotifications);
router.patch('/:id/read', auth_1.authenticate, notification_controller_1.markAsRead);
exports.default = router;
