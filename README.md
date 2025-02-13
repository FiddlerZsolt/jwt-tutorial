# JWT Authentication Server

A secure Node.js authentication server implementation using JSON Web Tokens (JWT) with refresh token functionality.

## Features

* User registration and login
* JWT-based authentication
* Refresh token mechanism
* HTTP-only cookies for token storage
* Rate limiting
* Security headers with Helmet
* Request logging

## Prerequisites

* Node.js (v14 or higher)
* npm or yarn

## Setup

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file in the root directory with:

```
JWT_SECRET=your_jwt_secret_here
REFRESH_TOKEN_SECRET=your_refresh_token_secret_here
PORT=3000
```

## Running the Server

Development mode:

```bash
npm run dev
```

Production mode:

```bash
npm start
```

## API Endpoints

### POST /register

Register a new user.

```json
{
  "username": "user123",
  "password": "password123"
}
```

### POST /login

Login with existing credentials.

```json
{
  "username": "user123",
  "password": "password123"
}
```

### POST /logout

Logout and invalidate tokens.

### POST /refresh-token

Get a new access token using refresh token.

### GET /protected

Example protected route (requires authentication).

## Security Features

* Access tokens expire after 15 minutes
* Refresh tokens expire after 30 days
* HTTP-only cookies prevent XSS attacks
* Rate limiting prevents brute force attacks
* Helmet middleware adds security headers
* Password hashing using bcrypt
* CSRF protection with SameSite cookies

## Dependencies

* express
* jsonwebtoken
* bcryptjs
* cookie-parser
* dotenv
* express-rate-limit
* helmet
* morgan
