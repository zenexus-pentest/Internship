# OWASP Juice Shop - Security Enhancements

## Overview
This repository demonstrates security enhancements made to OWASP Juice Shop, focusing on:
- Input validation and sanitization
- Password hashing
- JWT authentication
- Secure HTTP headers using Helmet.js

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/arslanenginner/Internship-Work.git
    cd Internship-Work
    ```
2. Install dependencies:
    ```bash
    npm install
    ```

3. Run the application:
    ```bash
    npm start
    ```

4. Access the application at `http://localhost:3000`.

## Security Enhancements
### 1. Input Validation
- Used `validator` to validate email inputs.

### 2. Password Hashing
- Used `bcrypt` to hash passwords securely.

### 3. JWT Authentication
- Implemented token-based authentication using `jsonwebtoken`.

### 4. Helmet.js for Secure HTTP Headers
- Used `helmet` to secure HTTP headers and prevent common attacks.

## Testing
To test the changes:
1. Create an account with a valid email.
2. Attempt to login using the JWT token.
3. Inspect headers for security measures.
