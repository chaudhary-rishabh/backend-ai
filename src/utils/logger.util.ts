import fs from 'fs';
import path from 'path';

class Logger {
    private logDir: string;

    constructor() {
        this.logDir = path.join(process.cwd(), 'logs');
        this.ensureLogDirectory();
    }

    private ensureLogDirectory(): void {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    private formatMessage(level: string, message: string, meta?: any): string {
        const timestamp = new Date().toISOString();
        const metaString = meta ? JSON.stringify(meta, null, 2) : '';
        return `[${timestamp}] ${level.toUpperCase()}: ${message} ${metaString}\n`;
    }

    private writeToFile(filename: string, message: string): void {
        const filePath = path.join(this.logDir, filename);
        fs.appendFileSync(filePath, message);
    }

    info(message: string, meta?: any): void {
        const formattedMessage = this.formatMessage('info', message, meta);
        console.log(formattedMessage.trim());
        this.writeToFile('app.log', formattedMessage);
    }

    error(message: string, meta?: any): void {
        const formattedMessage = this.formatMessage('error', message, meta);
        console.error(formattedMessage.trim());
        this.writeToFile('error.log', formattedMessage);
    }

    warn(message: string, meta?: any): void {
        const formattedMessage = this.formatMessage('warn', message, meta);
        console.warn(formattedMessage.trim());
        this.writeToFile('app.log', formattedMessage);
    }

    debug(message: string, meta?: any): void {
        if (process.env.NODE_ENV === 'development') {
            const formattedMessage = this.formatMessage('debug', message, meta);
            console.debug(formattedMessage.trim());
            this.writeToFile('debug.log', formattedMessage);
        }
    }
}

export const logger = new Logger();