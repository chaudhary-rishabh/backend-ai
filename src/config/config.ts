import dotenv from 'dotenv';

dotenv.config();

export const config = {
    NODE_ENV: process.env.NODE_ENV ?? 'development',
    PORT: process.env.PORT ?? 5000,
    MONGODB_URI: process.env.MONGODB_URI ?? 'mongodb://localhost:27017/jwt-auth',
    JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET ?? 'access-secret',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET ?? 'refresh-secret',
    JWT_RESET_SECRET: process.env.JWT_RESET_SECRET ?? 'reset-secret',
    ACCESS_TOKEN_EXPIRES_IN: process.env.ACCESS_TOKEN_EXPIRES_IN ?? '15m',
    REFRESH_TOKEN_EXPIRES_IN: process.env.REFRESH_TOKEN_EXPIRES_IN ?? '7d',
    RESET_TOKEN_EXPIRES_IN: process.env.RESET_TOKEN_EXPIRES_IN ?? '10m',
    CLIENT_URL: process.env.CLIENT_URL ?? 'http://localhost:3000',
    SMTP_HOST: process.env.SMTP_HOST ?? 'smtp.gmail.com',
    SMTP_PORT: parseInt(process.env.SMTP_PORT ?? '587'),
    SMTP_USER: process.env.SMTP_USER ?? '',
    SMTP_PASS: process.env.SMTP_PASS ?? '',
    EMAIL_FROM: process.env.EMAIL_FROM ?? ''
};