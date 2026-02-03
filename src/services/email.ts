import nodemailer from 'nodemailer';
import { config } from '../config';

const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: Number(config.email.port),
  secure: Number(config.email.port) === 465, // Use `true` for port 465, `false` for other ports
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
});

export const sendEmail = async (to: string, subject: string, text: string): Promise<void> => {
  try {
    const mailOptions = {
      from: config.email.user, // Sender address
      to: to, // List of receivers
      subject: subject, // Subject line
      text: text, // Plain text body
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error(`Failed to send email to ${to}:`, error);
    throw new Error('Failed to send email');
  }
};
