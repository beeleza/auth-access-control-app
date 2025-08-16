# Fullstack Authentication & Access Control App

A fullstack web application that implements **secure authentication** and **role-based access control** using **NestJS** and **Angular**.  
This project demonstrates modern authentication practices with **JWT**, **refresh tokens**, and **role-based route protection**.

---

## 🚀 Features

- **User Authentication**
  - Login and registration
  - Password hashing with bcrypt
  - JWT access & refresh token system

- **Access Control**
  - Role-based authorization
  - Protected API endpoints
  - Angular route guards for frontend protection

- **Tech Stack**
  - **Backend:** NestJS, TypeScript, JWT, bcrypt
  - **Frontend:** Angular, TypeScript, Angular Router
  - **Database:** (PostgreSQL, MySQL, or MongoDB — specify yours)
  - **API Communication:** REST over HTTPS

---

## 📂 Project Structure

```bash
/api
/client
.gitignore
README.md
```

## ⚙️ Installation

Follow these steps to set up and run the application:

1️⃣ Clone the repository
```bash
git clone https://github.com/beeleza/auth-access-control-app
cd auth-access-control-app
```

2️⃣ Start the backend services (Docker)

```bash
cd api
sudo docker compose up -d
```

3️⃣ Install backend dependencies and start the server

```bash
npm install
npm run start:dev
```

4️⃣ Install frontend dependencies and start the client

```bash
cd ../client
npm install
npm run start
```

The application should now be available at:

- Frontend: http://localhost:4200
- Backend API: http://localhost:3000
