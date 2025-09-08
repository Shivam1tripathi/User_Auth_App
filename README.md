# User_Auth_App

# 🔐 User Authentication App

A **Node.js + Express** authentication system with JWT tokens, email verification, role-based access control (RBAC), and secure login/logout with refresh tokens.  
Built with **MongoDB** as the database.

---

## ✨ Features

- ✅ User Signup with hashed password (bcrypt)
- ✅ Email verification after signup (via Nodemailer)
- ✅ Login with email & password
- ✅ JWT authentication (Access + Refresh tokens)
- ✅ Protected routes (e.g., `/profile`)
- ✅ Role-based access control (Admin/User)
- ✅ Logout (invalidate tokens)
- ✅ Rate limiting on login (to prevent brute force)
- ✅ Error handling (duplicate emails, wrong credentials, expired tokens)

---

## 🚀 Tech Stack

- **Backend:** Node.js, Express
- **Database:** MongoDB (Mongoose)
- **Authentication:** JWT (access & refresh tokens)
- **Security:** bcrypt, express-rate-limit, dotenv
- **Email Service:** Nodemailer (Gmail / SMTP)

---

## 📂 Project Structure

```
user-auth-app/
│── server.js               # App entry point
│── .env                    # Environment variables
│── package.json
│
├── Controller/
│   └── authController.js   # Auth logic (signup, login, logout, etc.)
│
├── Middleware/
│   └── authMiddleware.js   # Auth & RBAC middleware
│
├── Models/
│   └── User.js             # Mongoose user schema
│
├── Routes/
    └── authRoutes.js       # Auth routes

```

---

## ⚙️ Installation & Setup

### 1. Clone repo

```bash
git https://github.com/Shivam1tripathi/User_Auth_App.git
cd USER_AUTH_APP
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create `.env` file

Create a `.env` file in root with:

```
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_jwt_refresh_secret
EMAIL_USER=your_gmail_address
EMAIL_PASS=your_app_password   #Gmail app password Step Given Below
```

⚠️ For Gmail, generate an **App Passwords** instead of your regular password:  
For Creating app password go to gmail app
-Go to Manage Your Google account
-click on search bar and search **App Passwords** and click on it
-After verify click on create in your App Password With Name **Nodemailer**
-it will generate pass use it

👉 click here for more detail about **App Passwords** https://support.google.com/accounts/answer/185833

---

## ▶️ Run the app

```
npm run Server
```

Server runs on:

```
http://localhost:5000
---

## 🛠 API Endpoints

Post Man Collection link :- https://www.postman.com/shivam12tr/workspace/public/collection/33231756-1d6e6e43-dd34-4c84-be66-3fce92072d1f?action=share&creator=33231756

### Auth

- **POST** `/api/auth/signup` → Register new user
- **GET** `/api/auth/verify-email?token={}` → Verify user email
- **POST** `/api/auth/login` → Login & get tokens
- **POST** `/api/auth/logout` → Logout & invalidate tokens
- **POST** `/api/auth/refresh-token` → Get new access token using refresh token

### Protected

- **GET** `/api/auth/profile` → Get user profile (requires `Authorization: Bearer <token>`)
- **GET** `/api/auth/admin` → Admin-only route

---

## 🔑 JWT Authentication Flow

1. User signs up → gets email verification link.
2. After verification → can login.
3. On login → receives **accessToken (15 min)** & **refreshToken (7 days)**.
4. Access protected routes with `Authorization: Bearer <accessToken>`.
5. If access token expires → call `/refresh-token` with refresh token.
6. On logout → refresh token removed,but access token will work until it expired

## 📌 Notes

- Logout **does not immediately invalidate access token**
- Rate limiting applied on login to prevent brute-force.
- After Register make sure t0 verify email from gmail in same system where your server is running

---

✨ Happy Coding! 🚀
```
