import { Request } from 'express';
import { IUser } from '../models/user.model';

export interface AuthRequest extends Request {
    user?: IUser;
}

export interface JWTPayload {
    userId: string;
    email: string;
    iat?: number;
    exp?: number;
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
}