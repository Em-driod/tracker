import { Fido2Lib } from 'fido2-lib';

export const rpName = process.env.WEBAUTHN_RP_NAME || 'Your App Name';
export const rpId = process.env.WEBAUTHN_RP_ID || 'localhost'; // Use your domain name here in production
export const origin = process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'; // Use your app's origin in production

export const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: rpId,
  rpName: rpName,
  challengeSize: 128,
  attestation: 'direct', // 'none', 'indirect', 'direct', 'ent'
  cryptoParams: [-7, -257], // -7 for ES256, -257 for RS256
  // authenticatorAttachment: 'platform', // 'platform' or 'cross-platform'
  // authentatorRequireResidentKey: false,
  // authenticatorUserVerification: 'preferred', // 'required', 'preferred', 'discouraged'
});
