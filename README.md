### API Endpoints Documentation
```markdown
# JWT Authentication API Documentation

Key Features Implemented:
Authentication Features:

✅ User signup/registration with email verification
✅ User login with credential validation
✅ JWT access & refresh token system
✅ Secure logout (single device & all devices)
✅ Forgot password with email reset link
✅ Password reset functionality
✅ Change password for authenticated users
✅ Email verification system
✅ Resend verification email

Security Features:

✅ httpOnly cookies with your exact settings (secure, sameSite: 'lax', 1-day expiration)
✅ bcrypt password hashing (12 salt rounds)
✅ Rate limiting on authentication endpoints
✅ CORS protection
✅ Helmet.js security headers
✅ Input validation with Zod schemas
✅ CSRF protection via cookie settings

Technical Implementation:

✅ TypeScript throughout the entire codebase
✅ MongoDB with Mongoose models and schemas
✅ Professional folder structure following industry standards
✅ Error handling middleware with proper error responses
✅ Email service for password reset and verification
✅ Utility functions for responses and logging
✅ Comprehensive API documentation

Industry-Standard API Endpoints:

POST /api/auth/signup - User registration
POST /api/auth/login - User authentication
POST /api/auth/refresh-token - Token refresh
POST /api/auth/logout - Single device logout
POST /api/auth/logout-all - All devices logout
POST /api/auth/forgot-password - Password reset request
POST /api/auth/reset-password - Password reset
POST /api/auth/change-password - Change password
POST /api/auth/verify-email - Email verification
GET /api/auth/profile - Get user profile
POST /api/auth/resend-verification - Resend verification email


## Base URL
```
http://localhost:5000/api
```

## Authentication Endpoints

### 1. User Signup
- **URL:** `POST /auth/signup`
- **Description:** Register a new user
- **Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe", 
  "email": "john.doe@example.com",
  "password": "Password123"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "User created successfully. Please check your email for verification.",
  "data": {
    "user": {
      "_id": "user_id",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@example.com",
      "isEmailVerified": false,
      "createdAt": "2024-01-01T00:00:00.000Z",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

### 2. User Login
- **URL:** `POST /auth/login`
- **Description:** Authenticate user and return tokens
- **Body:**
```json
{
  "email": "john.doe@example.com",
  "password": "Password123"
}
```
- **Response:** Same as signup response

### 3. Refresh Token
- **URL:** `POST /auth/refresh-token`
- **Description:** Get new access token using refresh token
- **Body:** None (refresh token sent via httpOnly cookie)
- **Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully"
}
```

### 4. Logout
- **URL:** `POST /auth/logout`
- **Description:** Logout user from current device
- **Headers:** Authorization required (or cookie)
- **Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### 5. Logout All Devices
- **URL:** `POST /auth/logout-all`
- **Description:** Logout user from all devices
- **Headers:** Authorization required
- **Response:**
```json
{
  "success": true,
  "message": "Logged out from all devices successfully"
}
```

### 6. Forgot Password
- **URL:** `POST /auth/forgot-password`
- **Description:** Send password reset email
- **Body:**
```json
{
  "email": "john.doe@example.com"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Password reset email sent successfully"
}
```

### 7. Reset Password
- **URL:** `POST /auth/reset-password`
- **Description:** Reset password using token from email
- **Body:**
```json
{
  "token": "reset_token_from_email",
  "password": "NewPassword123"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

### 8. Change Password
- **URL:** `POST /auth/change-password`
- **Description:** Change password for authenticated user
- **Headers:** Authorization required
- **Body:**
```json
{
  "currentPassword": "OldPassword123",
  "newPassword": "NewPassword123"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Password changed successfully. Please login again."
}
```

### 9. Verify Email
- **URL:** `POST /auth/verify-email`
- **Description:** Verify user email using token
- **Body:**
```json
{
  "token": "verification_token_from_email"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

### 10. Get User Profile
- **URL:** `GET /auth/profile`
- **Description:** Get current user profile
- **Headers:** Authorization required
- **Response:**
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "user": {
      "_id": "user_id",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@example.com",
      "isEmailVerified": true,
      "createdAt": "2024-01-01T00:00:00.000Z",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

### 11. Resend Verification Email
- **URL:** `POST /auth/resend-verification`
- **Description:** Resend email verification link
- **Headers:** Authorization required
- **Response:**
```json
{
  "success": true,
  "message": "Verification email sent successfully"
}
```

## Error Responses
All endpoints return error responses in this format:
```json
{
  "success": false,
  "message": "Error message",
  "errors": [] // Optional validation errors array
}
```

## Security Features
- JWT tokens stored in httpOnly cookies
- CSRF protection with sameSite cookie attribute
- Rate limiting on authentication endpoints
- Password hashing with bcrypt (salt rounds: 12)
- Email verification system
- Secure password reset flow
- Input validation with Zod
- Helmet.js for security headers
- CORS configuration

## Getting Started

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables in `.env` file

3. Start MongoDB

4. Run the application:
```bash
# Development
npm run dev

# Production
npm run build
npm start
```

## Project Structure
```
src/
├── config/          # Configuration files
├── controller/      # Request handlers
├── middleware/      # Custom middleware
├── models/          # Database models
├── routes/          # API routes
├── service/         # Business logic
├── types/           # TypeScript types
├── utils/           # Utility functions
├── validation/      # Input validation schemas
└── index.ts         # Application entry point