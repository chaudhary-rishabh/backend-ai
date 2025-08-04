export const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    INTERNAL_SERVER_ERROR: 500
} as const;

export const MESSAGES = {
    SUCCESS: {
        USER_CREATED: 'User created successfully',
        LOGIN_SUCCESS: 'Login successful',
        LOGOUT_SUCCESS: 'Logout successful',
        TOKEN_REFRESHED: 'Token refreshed successfully',
        PASSWORD_RESET_EMAIL_SENT: 'Password reset email sent successfully',
        PASSWORD_RESET_SUCCESS: 'Password reset successfully',
        EMAIL_VERIFIED: 'Email verified successfully',
        PASSWORD_CHANGED: 'Password changed successfully',
        PROFILE_RETRIEVED: 'Profile retrieved successfully',
        VERIFICATION_EMAIL_SENT: 'Verification email sent successfully'
    },
    ERROR: {
        USER_EXISTS: 'User already exists with this email',
        INVALID_CREDENTIALS: 'Invalid email or password',
        USER_NOT_FOUND: 'User not found',
        INVALID_TOKEN: 'Invalid token',
        TOKEN_EXPIRED: 'Token expired',
        ACCESS_TOKEN_NOT_FOUND: 'Access token not found',
        REFRESH_TOKEN_NOT_FOUND: 'Refresh token not found',
        INVALID_REFRESH_TOKEN: 'Invalid refresh token',
        USER_NOT_AUTHENTICATED: 'User not authenticated',
        EMAIL_NOT_VERIFIED: 'Email is not verified',
        EMAIL_ALREADY_VERIFIED: 'Email is already verified',
        CURRENT_PASSWORD_INCORRECT: 'Current password is incorrect',
        RESET_TOKEN_INVALID: 'Password reset token is invalid or has expired',
        VERIFICATION_TOKEN_INVALID: 'Email verification token is invalid or has expired'
    }
} as const;

export const COOKIE_NAMES = {
    ACCESS_TOKEN: 'accessToken',
    REFRESH_TOKEN: 'refreshToken'
} as const;

export const TOKEN_TYPES = {
    ACCESS: 'access',
    REFRESH: 'refresh',
    RESET: 'reset',
    EMAIL_VERIFICATION: 'emailVerification'
} as const;