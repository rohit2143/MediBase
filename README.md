# 🏥 MediBase

MediBase is a healthcare management system designed to help clinics and healthcare providers **store, manage, and organize patient medical records** efficiently.

This application focuses on providing a secure and scalable backend for handling patient data, authentication, and database management.

---

## ✨ Key Features
- 🔐 User Authentication (JWT-based)
- 🧾 Secure storage of patient records
- 📊 Scalable architecture for future modules
- ⚡ Built with modern backend technologies

---

## 💻 Tech Stack

| Technology  | Purpose |
|-------------|---------|
| Node.js + Express | Backend framework |
| MongoDB | Database for storing records |
| JWT (JSON Web Token) | Authentication and security |
| dotenv | Environment variable management |

---

## 🚀 Getting Started

Follow these steps to set up MediBase locally:

```bash
# Clone the repository
git clone https://github.com/rohit2143/MediBase.git
cd MediBase/hdims/backend

# Install dependencies
npm install

# Start the development server
npm start


MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
PORT=5000


🛣️ Roadmap

✅ Initial backend setup (Express + MongoDB)
⬜ Add patient management routes
⬜ Implement role-based access (Doctor/Admin)
⬜ Build frontend (React/Next.js)
⬜ Deploy on cloud (Render/Heroku)
