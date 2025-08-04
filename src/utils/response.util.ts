import { Response } from 'express';

interface ApiResponse<T = any> {
    success: boolean;
    message: string;
    data?: T;
    errors?: any[];
}

export class ResponseUtil {
    static success<T>(res: Response, message: string, data?: T, statusCode: number = 200): Response {
        const response: ApiResponse<T> = {
            success: true,
            message,
            ...(data && { data })
        };

        return res.status(statusCode).json(response);
    }

    static error(res: Response, message: string, statusCode: number = 500, errors?: any[]): Response {
        const response: ApiResponse = {
            success: false,
            message,
            ...(errors && { errors })
        };

        return res.status(statusCode).json(response);
    }

    static validationError(res: Response, errors: any[]): Response {
        return this.error(res, 'Validation failed', 400, errors);
    }

    static unauthorized(res: Response, message: string = 'Unauthorized'): Response {
        return this.error(res, message, 401);
    }

    static forbidden(res: Response, message: string = 'Forbidden'): Response {
        return this.error(res, message, 403);
    }

    static notFound(res: Response, message: string = 'Resource not found'): Response {
        return this.error(res, message, 404);
    }

    static conflict(res: Response, message: string = 'Resource already exists'): Response {
        return this.error(res, message, 409);
    }

    static internalError(res: Response, message: string = 'Internal server error'): Response {
        return this.error(res, message, 500);
    }
}