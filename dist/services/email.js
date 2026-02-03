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
exports.sendEmail = void 0;
// For this example, we'll use a mock email service.
// In a real application, you would configure this with a real email provider.
const sendEmail = (to, subject, text) => __awaiter(void 0, void 0, void 0, function* () {
    console.log(`Sending email to ${to} with subject "${subject}" and text "${text}"`);
    return Promise.resolve();
});
exports.sendEmail = sendEmail;
