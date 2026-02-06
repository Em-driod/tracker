"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Category = void 0;
const mongoose_1 = require("mongoose");
const categorySchema = new mongoose_1.Schema({
    userId: { type: mongoose_1.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    parent: { type: mongoose_1.Schema.Types.ObjectId, ref: 'Category' },
    budget: { type: Number, default: 0 },
    icon: { type: String },
    color: { type: String },
    isDefault: { type: Boolean, default: false },
}, { timestamps: true });
// Ensure a user can't have duplicate categories with the same name and parent
categorySchema.index({ userId: 1, name: 1, parent: 1 }, { unique: true });
exports.Category = (0, mongoose_1.model)('Category', categorySchema);
