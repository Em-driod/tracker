import { Schema, model, Document, Types } from 'mongoose';

/**
 * OTP Interface & Schema
 */
export interface IOtp extends Document {
  userId: Types.ObjectId;
  code: string;
  expiresAt: Date;
  type: 'REGISTER' | 'LOGIN' | 'RESET';
}

const otpSchema = new Schema<IOtp>({
  userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  type: { type: String, required: true, enum: ['REGISTER', 'LOGIN', 'RESET'] },
});

export const Otp = model<IOtp>('Otp', otpSchema);

/**
 * WebAuthn Credential Interface
 */
export interface IWebAuthnCredential {
  credID: Buffer;
  publicKey: Buffer;
  counter: number;
  credType: string;
  transports?: string[];
  aaguid: Buffer;
  fmt: string;
  attestationCert?: Buffer;
  userHandle?: Buffer;
}

/**
 * User Interface
 * Added all fields used in your controller to prevent 'never' or 'does not exist' errors.
 */
export interface IUser extends Document {
  _id: Types.ObjectId;
  fullName: string;
  email: string;
  username: string;
  mobile?: string;
  dateOfBirth: Date;
  password?: string;
  isVerified: boolean;
  lastActivityAt: Date;
  webauthn_credentials?: IWebAuthnCredential[];
  currentWebAuthnChallenge?: string;
  profileImage?: string;
  pin?: string;
  isFingerprintEnabled?: boolean;
  notificationSettings?: {
    pushEnabled: boolean;
    emailEnabled: boolean;
  };
  identificationImage?: string;
}

/**
 * User Schema
 */
const userSchema = new Schema<IUser>({
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

export const User = model<IUser>('User', userSchema);