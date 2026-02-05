import { Request, Response } from 'express';
import { CustomRequest } from '../middleware/auth';
import { z } from 'zod';
import { hashPassword, comparePassword, checkPasswordStrength } from '../utils/password';
import { generateToken, verifyToken } from '../utils/jwt';
import { sendEmail } from '../services/email';
import { generateOtp } from '../utils/otp';
import { User, Otp, IUser, IOtp } from '../models/user.model';
import { config } from '../config';

// --- Validation Schemas ---
const registerSchema = z.object({
  fullName: z.string(),
  email: z.string().email(),
  dateOfBirth: z.string().refine((val) => !isNaN(Date.parse(val)), { message: "Invalid date format" }),
  password: z.string().min(8, { message: "Password must be at least 8 characters long" }),
  mobile: z.string().optional(),
});

const loginSchema = z.object({
  identifier: z.string(),
  password: z.string(),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const verifyOtpSchema = z.object({
  email: z.string().email(),
  otp: z.string(),
});

const verifyRegistrationOtpSchema = z.object({
  email: z.string().email(),
  otp: z.string(),
});

const resetPasswordSchema = z.object({
  resetToken: z.string(),
  newPassword: z.string().min(8, { message: "Password must be at least 8 characters long" }),
});

const verifyLoginOtpSchema = z.object({
  identifier: z.string(),
  otp: z.string(),
});

const initWebAuthnRegistrationSchema = z.object({
  email: z.string().email(),
});

const completeWebAuthnRegistrationSchema = z.object({
  email: z.string().email(),
  attestationResponse: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      attestationObject: z.string(),
      clientDataJSON: z.string(),
    }),
    type: z.string(),
    clientExtensionResults: z.object({}).passthrough().optional(),
    transports: z.array(z.string()).optional(),
  }),
});

const initWebAuthnLoginSchema = z.object({
  identifier: z.string(),
});

const completeWebAuthnLoginSchema = z.object({
  identifier: z.string(),
  assertionResponse: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      authenticatorData: z.string(),
      clientDataJSON: z.string(),
      signature: z.string(),
      userHandle: z.string().optional(),
    }),
    type: z.string(),
    clientExtensionResults: z.object({}).passthrough().optional(),
  }),
});

// --- Controller Functions ---


export const register = async (req: Request, res: Response) => {
  try {
    const { fullName, email, dateOfBirth: dobString, password, mobile } = registerSchema.parse(req.body);

    const passwordStrength = checkPasswordStrength(password);
    if (passwordStrength === 'weak') {
      return res.status(400).json({ message: 'Password is too weak. Please include uppercase, lowercase, numbers, and symbols.' });
    }

    const dateOfBirth = new Date(dobString);
    const age = new Date().getFullYear() - dateOfBirth.getFullYear();
    if (age < 13) {
      return res.status(400).json({ message: 'You must be at least 13 years old to register' });
    }

    // Generate username from email if not provided (e.g., john@doe.com -> john_doe_123)
    const username = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '_') + '_' + Math.floor(Math.random() * 1000);

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already exists' });
    }

    const hashedPassword = await hashPassword(password);

    const newUser = new User({
      fullName,
      email,
      username,
      mobile,
      dateOfBirth,
      password: hashedPassword,
      isVerified: false, // Set isVerified to false initially
    });
    await newUser.save();

    // Generate and send OTP for registration verification
    const otp = generateOtp();
    const hashedOtp = await hashPassword(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    const otpDoc = await Otp.create({ userId: newUser._id, code: hashedOtp, expiresAt, type: 'REGISTER' });

    await sendEmail(email, 'Verify Your Account - OTP', `Your OTP for account verification is: ${otp}`);

    res.status(200).json({ message: 'Registration successful! Please verify your email with the OTP sent to your inbox.' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


export const login = async (req: Request, res: Response) => {
  try {
    const { identifier, password } = loginSchema.parse(req.body);

    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });

    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(401).json({ message: 'Please verify your email to log in.' });
    }

    // Check for inactivity (2 weeks = 14 days * 24 hours * 60 minutes * 60 seconds * 1000 milliseconds)
    const twoWeeksAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
    const isInactive = !user.lastActivityAt || user.lastActivityAt < twoWeeksAgo;

    if (isInactive) {
      const otp = generateOtp();
      const hashedOtp = await hashPassword(otp);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

      // Store OTP for login re-verification
      await Otp.findOneAndUpdate(
        { userId: user._id, type: 'LOGIN' },
        { code: hashedOtp, expiresAt, type: 'LOGIN' },
        { upsert: true, new: true }
      );

      await sendEmail(user.email, 'Login Verification OTP', `Your OTP for login verification is: ${otp}`);
      return res.status(202).json({ message: 'Account inactive. An OTP has been sent to your email for login verification.' });
    }

    // If active, proceed with normal login
    user.lastActivityAt = new Date();
    await user.save();

    const token = generateToken({ userId: user._id.toString() }, '1h');

    res.status(200).json({
      message: 'Login successful',
      token
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = forgotPasswordSchema.parse(req.body);
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ message: 'If a user with that email exists, an OTP has been sent.' });
    }

    const otp = generateOtp();
    const hashedOtp = await hashPassword(otp);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    // Save/Update OTP in the Otp collection
    await Otp.findOneAndUpdate(
      { userId: user._id, type: 'RESET' },
      { code: hashedOtp, expiresAt, type: 'RESET' },
      { upsert: true, new: true }
    );

    await sendEmail(email, 'Your Password Reset OTP', `Your OTP is: ${otp}`);
    res.json({ message: 'If a user with that email exists, an OTP has been sent.' });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = verifyOtpSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    const otpRecord = await Otp.findOne({ userId: user._id, type: 'RESET' });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (new Date() > otpRecord.expiresAt) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    const isOtpValid = await comparePassword(otp, otpRecord.code);
    if (!isOtpValid) return res.status(400).json({ message: 'Invalid OTP' });

    // Cleanup
    await Otp.deleteOne({ _id: otpRecord._id });

    const resetToken = generateToken({ userId: user._id.toString() }, '15m');

    res.json({ resetToken });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { resetToken, newPassword } = resetPasswordSchema.parse(req.body);

    const passwordStrength = checkPasswordStrength(newPassword);
    if (passwordStrength === 'weak') {
      return res.status(400).json({ message: 'Password is too weak. Please include uppercase, lowercase, numbers, and symbols.' });
    }

    const decoded = verifyToken(resetToken);

    if (!decoded) return res.status(400).json({ message: 'Invalid or expired reset token' });

    const hashedPassword = await hashPassword(newPassword);
    await User.findByIdAndUpdate((decoded as any).userId, { password: hashedPassword });

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyRegistrationOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = verifyRegistrationOtpSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP or user not found' });
    }

    const otpRecord = await Otp.findOne({ userId: user._id, type: 'REGISTER' });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid OTP or user not found' });
    }

    if (new Date() > otpRecord.expiresAt) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    const isOtpValid = await comparePassword(otp, otpRecord.code);
    if (!isOtpValid) return res.status(400).json({ message: 'Invalid OTP' });

    // Mark user as verified
    user.isVerified = true;
    await user.save();

    // Cleanup OTP
    await Otp.deleteOne({ _id: otpRecord._id });

    res.status(200).json({ message: 'Email verified successfully! You can now log in.' });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const verifyLoginOtp = async (req: Request, res: Response) => {
  try {
    const { identifier, otp } = verifyLoginOtpSchema.parse(req.body);

    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });

    if (!user) {
      return res.status(400).json({ message: 'Invalid OTP or user not found' });
    }

    const otpRecord = await Otp.findOne({ userId: user._id, type: 'LOGIN' });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid OTP or user not found' });
    }

    if (new Date() > otpRecord.expiresAt) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    const isOtpValid = await comparePassword(otp, otpRecord.code);
    if (!isOtpValid) return res.status(400).json({ message: 'Invalid OTP' });

    // Cleanup OTP
    await Otp.deleteOne({ _id: otpRecord._id });
    user.lastActivityAt = new Date(); // Update last activity on successful OTP login
    await user.save();

    const token = generateToken({ userId: user._id.toString() }, '1h');

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ message: error.issues });
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const initWebAuthnRegistration = async (req: Request, res: Response) => {
  try {
    const { email } = initWebAuthnRegistrationSchema.parse(req.body);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const authenticatorSelection = {
      authenticatorAttachment: 'cross-platform', // Can be 'platform' or 'cross-platform'
      userVerification: 'preferred', // 'required', 'preferred', or 'discouraged'
      residentKey: 'preferred', // 'required', 'preferred', or 'discouraged' (for discoverable credentials/passkeys)
    };

    const attestationOptions = await config.webauthn.fido2.attestationOptions({
      user: {
        id: user._id.toString(),
        name: user.email,
        displayName: user.fullName,
      },
      authenticatorSelection: authenticatorSelection,
    } as any);

    // Store the challenge for verification in the next step
    user.currentWebAuthnChallenge = Buffer.from(attestationOptions.challenge).toString('base64url');
    await user.save();

    res.status(200).json(attestationOptions);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const completeWebAuthnRegistration = async (req: Request, res: Response) => {
  try {
    const { email, attestationResponse } = completeWebAuthnRegistrationSchema.parse(req.body);

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.currentWebAuthnChallenge) {
      return res.status(400).json({ message: 'No WebAuthn registration in progress for this user.' });
    }

    const attestationExpectations = {
      challenge: user.currentWebAuthnChallenge,
      origin: config.webauthn.origin,
      factor: 'either' as any,
    };

    // Convert string fields to Buffer as required by fido2-lib
    const convertedAttestationResponse = {
      ...attestationResponse,
      id: Buffer.from(attestationResponse.id, 'base64url'),
      rawId: Buffer.from(attestationResponse.rawId, 'base64url'),
      response: {
        attestationObject: Buffer.from(attestationResponse.response.attestationObject, 'base64url'),
        clientDataJSON: Buffer.from(attestationResponse.response.clientDataJSON, 'base64url'),
      },
    };

    const attestationResult = await config.webauthn.fido2.attestationResult(convertedAttestationResponse as any, attestationExpectations);

    const {
      credId,
      publicKey,
      counter,
      credType,
      aaguid,
      fmt,
      attestationCert,
      userHandle,
      transports,
    }: any = attestationResult.authnrData;

    const newCredential = {
      credID: Buffer.from(credId),
      publicKey: Buffer.from(publicKey),
      counter: counter,
      credType: credType,
      transports: transports,
      aaguid: Buffer.from(aaguid),
      fmt: fmt,
      attestationCert: attestationCert ? Buffer.from(attestationCert) : undefined,
      userHandle: userHandle ? Buffer.from(userHandle) : undefined,
    };

    if (!user.webauthn_credentials) {
      user.webauthn_credentials = [];
    }
    user.webauthn_credentials.push(newCredential);
    user.currentWebAuthnChallenge = undefined; // Clear the challenge after use
    await user.save();

    res.status(200).json({ message: 'WebAuthn registration successful!' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const initWebAuthnLogin = async (req: Request, res: Response) => {
  try {
    const { identifier } = initWebAuthnLoginSchema.parse(req.body);

    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.webauthn_credentials || user.webauthn_credentials.length === 0) {
      return res.status(400).json({ message: 'No WebAuthn credentials registered for this user.' });
    }

    const allowCredentials = user.webauthn_credentials.map(cred => ({
      id: cred.credID,
      type: 'public-key',
      transports: cred.transports,
    }));

    const assertionOptions = await config.webauthn.fido2.assertionOptions({
      allowCredentials: allowCredentials,
      userVerification: 'preferred',
      rpId: config.webauthn.rpId,
      timeout: 60000, // Example timeout, should be configurable
    } as any);

    user.currentWebAuthnChallenge = Buffer.from(assertionOptions.challenge).toString('base64url');
    await user.save();

    res.status(200).json(assertionOptions);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const completeWebAuthnLogin = async (req: Request, res: Response) => {
  try {
    const { identifier, assertionResponse } = completeWebAuthnLoginSchema.parse(req.body);

    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.currentWebAuthnChallenge) {
      return res.status(400).json({ message: 'No WebAuthn login in progress for this user.' });
    }

    if (!user.webauthn_credentials || user.webauthn_credentials.length === 0) {
      return res.status(400).json({ message: 'No WebAuthn credentials registered for this user.' });
    }

    // Find the credential used for this assertion
    const authenticator = user.webauthn_credentials.find(
      (cred) => cred.credID.toString('base64url') === assertionResponse.rawId
    );

    if (!authenticator) {
      return res.status(400).json({ message: 'Authenticator not found for this user.' });
    }

    const assertionExpectations = {
      challenge: user.currentWebAuthnChallenge,
      origin: config.webauthn.origin,
      publicKey: authenticator.publicKey.toString('base64url'),
      prevCounter: authenticator.counter,
      userHandle: Buffer.from(user._id.toString()).toString('base64url'),
      factor: 'either' as any,
    };

    const convertedAssertionResponse = {
      ...assertionResponse,
      id: Buffer.from(assertionResponse.id, 'base64url'),
      rawId: Buffer.from(assertionResponse.rawId, 'base64url'),
      response: {
        authenticatorData: Buffer.from(assertionResponse.response.authenticatorData, 'base64url'),
        clientDataJSON: Buffer.from(assertionResponse.response.clientDataJSON, 'base64url'),
        signature: Buffer.from(assertionResponse.response.signature, 'base64url'),
        userHandle: assertionResponse.response.userHandle ? Buffer.from(assertionResponse.response.userHandle, 'base64url') : undefined,
      },
    };

    const assertionResult = await config.webauthn.fido2.assertionResult(convertedAssertionResponse as any, assertionExpectations);

    // Update the counter
    (authenticator as any).counter = (assertionResult.authnrData as any).counter;

    user.currentWebAuthnChallenge = undefined; // Clear the challenge
    user.lastActivityAt = new Date(); // Update last activity on successful login
    await user.save();

    const token = generateToken({ userId: user._id.toString() }, '1h');

    res.status(200).json({ message: 'WebAuthn login successful!', token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.issues });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};