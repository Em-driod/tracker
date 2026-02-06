"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fido2 = exports.origin = exports.rpId = exports.rpName = void 0;
const fido2_lib_1 = require("fido2-lib");
exports.rpName = process.env.WEBAUTHN_RP_NAME || 'Your App Name';
exports.rpId = process.env.WEBAUTHN_RP_ID || 'localhost'; // Use your domain name here in production
exports.origin = process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'; // Use your app's origin in production
exports.fido2 = new fido2_lib_1.Fido2Lib({
    timeout: 60000,
    rpId: exports.rpId,
    rpName: exports.rpName,
    challengeSize: 128,
    attestation: 'direct', // 'none', 'indirect', 'direct', 'ent'
    cryptoParams: [-7, -257], // -7 for ES256, -257 for RS256
    // authenticatorAttachment: 'platform', // 'platform' or 'cross-platform'
    // authentatorRequireResidentKey: false,
    // authenticatorUserVerification: 'preferred', // 'required', 'preferred', 'discouraged'
});
