import nodemailer from 'nodemailer';
import { config } from '../config/config';

class EmailService {
    private transporter: nodemailer.Transporter;

    constructor() {
        this.transporter = nodemailer.createTransporter({
            host: config.SMTP_HOST,
            port: config.SMTP_PORT,
            secure: false,
            auth: {
                user: config.SMTP_USER,
                pass: config.SMTP_PASS
            }
        });
    }

    async sendResetPasswordEmail(email: string, resetToken: string): Promise<void> {
        const resetUrl = `${config.CLIENT_URL}/reset-password?token=${resetToken}`;

        const mailOptions = {
            from: config.EMAIL_FROM,
            to: email,
            subject: 'Password Reset Request',
            html: `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Reset Password</a>
          <p style="color: #666; font-size: 14px;">This link will expire in 10 minutes.</p>
          <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
        </div>
      `
        };

        await this.transporter.sendMail(mailOptions);
    }

    async sendEmailVerification(email: string, verificationToken: string): Promise<void> {
        const verificationUrl = `${config.CLIENT_URL}/verify-email?token=${verificationToken}`;

        const mailOptions = {
            from: config.EMAIL_FROM,
            to: email,
            subject: 'Email Verification',
            html: `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Please verify your email address by clicking the link below:</p>
          <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Verify Email</a>
          <p style="color: #666; font-size: 14px;">This link will expire in 24 hours.</p>
        </div>
      `
        };

        await this.transporter.sendMail(mailOptions);
    }
}

export const emailService = new EmailService();