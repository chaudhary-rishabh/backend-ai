import { Request, Response, NextFunction } from 'express';
import { authService } from '../service/auth.service';
import { AuthRequest } from '../types/auth.types';

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
};

class AuthController {
    async signup(req: Request, res: Response, next: NextFunction) {
        try {
            const { firstName, lastName, email, password } = req.body;

            const { user, tokens } = await authService.signup({
                firstName,
                lastName,
                email,
                password
            });

            // Set cookies
            res.cookie('accessToken', tokens.accessToken, cookieOptions);
            res.cookie('refreshToken', tokens.refreshToken, {
                ...cookieOptions,
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days for refresh token
            });

            res.status(201).json({
                success: true,
                message: 'User created successfully. Please check your email for verification.',
                data: { user }
            });
        } catch (error: any) {
            next(error);
        }
    }

    async login(req: Request, res: Response, next: NextFunction) {
        try {
            const { email, password } = req.body;

            const { user, tokens } = await authService.login(email, password);

            // Set cookies
            res.cookie('accessToken', tokens.accessToken, cookieOptions);
            res.cookie('refreshToken', tokens.refreshToken, {
                ...cookieOptions,
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days for refresh token
            });

            res.status(200).json({
                success: true,
                message: 'Login successful',
                data: { user }
            });
        } catch (error: any) {
            if (error.message === 'Invalid credentials') {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }
            next(error);
        }
    }

    async refreshToken(req: Request, res: Response, next: NextFunction) {
        try {
            const refreshToken = req.cookies.refreshToken;

            if (!refreshToken) {
                return res.status(401).json({
                    success: false,
                    message: 'Refresh token not found'
                });
            }

            const tokens = await authService.refreshToken(refreshToken);

            // Set new cookies
            res.cookie('accessToken', tokens.accessToken, cookieOptions);
            res.cookie('refreshToken', tokens.refreshToken, {
                ...cookieOptions,
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days for refresh token
            });

            res.status(200).json({
                success: true,
                message: 'Token refreshed successfully'
            });
        } catch (error: any) {
            if (error.message === 'Invalid refresh token') {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token'
                });
            }
            next(error);
        }
    }

    async logout(req: AuthRequest, res: Response, next: NextFunction) {
        try {
            const refreshToken = req.cookies.refreshToken;
            const userId = req.user?._id.toString();

            if (userId && refreshToken) {
                await authService.logout(userId, refreshToken);
            }

            // Clear cookies
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');

            res.status(200).json({
                success: true,
                message: 'Logout successful'
            });
        } catch (error: any) {
            next(error);
        }
    }

    async logoutAll(req: AuthRequest, res: Response, next: NextFunction) {
        try {
            const userId = req.user?._id.toString();

            if (userId) {
                await authService.logoutAll(userId);
            }

            // Clear cookies
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');

            res.status(200).json({
                success: true,
                message: 'Logged out from all devices successfully'
            });
        } catch (error: any) {
            next(error);
        }
    }

    async forgotPassword(req: Request, res: Response, next: NextFunction) {
        try {
            const { email } = req.body;

            await authService.forgotPassword(email);

            res.status(200).json({
                success: true,
                message: 'Password reset email sent successfully'
            });
        } catch (error: any) {
            if (error.message === 'User not found with this email') {
                return res.status(404).json({
                    success: false,
                    message: 'User not found with this email'
                });
            }
            next(error);
        }
    }

    async resetPassword(req: Request, res: Response, next: NextFunction) {
        try {
            const { token, password } = req.body;

            await authService.resetPassword(token, password);

            res.status(200).json({
                success: true,
                message: 'Password reset successfully'
            });
        } catch (error: any) {
            if (error.message === 'Password reset token is invalid or has expired') {
                return res.status(400).json({
                    success: false,
                    message: 'Password reset token is invalid or has expired'
                });
            }
            next(error);
        }
    }

    async verifyEmail(req: Request, res: Response, next: NextFunction) {
        try {
            const { token } = req.body;

            await authService.verifyEmail(token);

            res.status(200).json({
                success: true,
                message: 'Email verified successfully'
            });
        } catch (error: any) {
            if (error.message === 'Email verification token is invalid or has expired') {
                return res.status(400).json({
                    success: false,
                    message: 'Email verification token is invalid or has expired'
                });
            }
            next(error);
        }
    }

    async changePassword(req: AuthRequest, res: Response, next: NextFunction) {
        try {
            const { currentPassword, newPassword } = req.body;
            const userId = req.user?._id.toString();

            if (!userId) {
                return res.status(401).json({
                    success: false,
                    message: 'User not authenticated'
                });
            }

            await authService.changePassword(userId, currentPassword, newPassword);

            // Clear cookies to force re-login
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');

            res.status(200).json({
                success: true,
                message: 'Password changed successfully. Please login again.'
            });
        } catch (error: any) {
            if (error.message === 'Current password is incorrect') {
                return res.status(400).json({
                    success: false,
                    message: 'Current password is incorrect'
                });
            }
            next(error);
        }
    }

    async getProfile(req: AuthRequest, res: Response, next: NextFunction) {
        try {
            res.status(200).json({
                success: true,
                message: 'Profile retrieved successfully',
                data: { user: req.user }
            });
        } catch (error: any) {
            next(error);
        }
    }

    async resendVerificationEmail(req: AuthRequest, res: Response, next: NextFunction) {
        try {
            const user = req.user;

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: 'User not authenticated'
                });
            }

            if (user.isEmailVerified) {
                return res.status(400).json({
                    success: false,
                    message: 'Email is already verified'
                });
            }

            // Generate new verification token
            const verificationToken = authService.generateEmailVerificationToken();
            user.emailVerificationToken = verificationToken;
            user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

            await user.save();

            // Send verification email
            const { emailService } = await import('../service/email.service');
            await emailService.sendEmailVerification(user.email, verificationToken);

            res.status(200).json({
                success: true,
                message: 'Verification email sent successfully'
            });
        } catch (error: any) {
            next(error);
        }
    }
}

export const authController = new AuthController();