# 📚 ClassiX – Smart Attendance & Academic Management Platform

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen.svg)](http://classix.onrender.com/)
[![GitHub Repo](https://img.shields.io/badge/github-ClassiX-blue.svg)](https://github.com/Classi-X/ClassiX)

A **next-generation academic and attendance management platform** built for schools, colleges, and universities.  
ClassiX combines **manual, QR, and biometric attendance**, **parent engagement**, **analytics**, **chat**, and an **AI-powered chatbot** — all in one unified system.

---

## 🌟 Overview

ClassiX modernizes institutional workflows by digitizing attendance and streamlining communication among **administrators, teachers, students, and parents**.  

It offers multiple attendance modes (manual, QR codes, fingerprint, face recognition), real-time analytics to identify at-risk students, automated parent notifications, and built-in chat for collaboration.  
The platform is accessible via **web** and **Android app**, with **Windows/macOS/iOS clients** planned.

👉 **Live Website:** [http://classix.onrender.com/](http://classix.onrender.com/)  
👉 **GitHub Repository:** [https://github.com/Classi-X/ClassiX](https://github.com/Classi-X/ClassiX)

---

## ✨ Features

- 🔑 **Secure Role-based Registration & Login**  
  PIN-based teacher/student onboarding, OTP-based parent verification, hashed passwords.

- 📝 **Flexible Attendance Capture**  
  - Manual marking (no duplicates)  
  - QR-based (one-time, persistent, rotating)  
  - Biometric fingerprint enrollment & matching  
  - Webcam-based face recognition (OpenCV)  
  - Wi-Fi restrictions for on-campus validation  

- 📊 **Analytics & Insights**  
  - Attendance percentages & trends (linear regression)  
  - At-risk student identification (<75% or <60%)  
  - Visual dashboards with charts & heatmaps  

- 📢 **Parent Communication & Portal**  
  - Automated alerts (email/WhatsApp via Twilio)  
  - Monthly attendance reports  
  - Parent dashboard with live statistics  

- 💬 **Chat & Collaboration**  
  One-to-one real-time messaging with unread notifications.

- 🤖 **AI Chatbot Assistant**  
  FAQ-based + AI API integration for instant help.

- 📂 **Institution & Class Management**  
  Institution setup, class/stream/degree configuration, teacher self-assignment.

- ⬆️ **Student Promotions & Bulk Import**  
  Bulk student additions, automated promotions with audit logs.

- 🔍 **Search & Reporting**  
  User and attendance record search, CSV export.

- 🛡️ **Security & Privacy**  
  Hashed passwords, CSRF tokens, OTP verification, encrypted data storage.

- 📱 **Responsive Web & Mobile App**  
  Bootstrap UI with role-specific navigation.

---

## ⚙️ Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/Classi-X/ClassiX.git
cd ClassiX
````

### 2. Create Virtual Environment & Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Set Up Environment Variables

Create a `.env` file in the project root:

```ini
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///classix.db   # or PostgreSQL URI
MAIL_SERVER=smtp.example.com
MAIL_USERNAME=your_email
MAIL_PASSWORD=your_password
TWILIO_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
QR_EXPIRY=900
FINGERPRINT_ENABLE=True
```

### 4. Initialize Database

```bash
flask db upgrade
```

### 5. Run the Server

```bash
python app.py
```

Visit: `http://127.0.0.1:5000/`

---

## 🚀 Usage Instructions

* **Super-admin** creates the first institution and admin accounts.
* **Admins** configure institution details, generate PINs, approve users, and manage analytics.
* **Teachers** self-assign classes, mark attendance, and communicate with parents.
* **Students** log in to view attendance or mark presence via QR/biometric.
* **Parents** verify via OTP to access their child’s attendance dashboard.

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask, Flask-Login, Flask-Mail, SQLAlchemy)
* **Database:** SQLite / PostgreSQL
* **Frontend:** Jinja2 Templates, Bootstrap, Chart.js
* **Biometrics:** OpenCV (face recognition), PyFingerprint (fingerprints)
* **Analytics:** NumPy, Pandas, scikit-learn
* **Messaging/Notifications:** Twilio (WhatsApp), SMTP email
* **Other:** Pillow, qrcode, pytz

---

## 🏗️ Project Structure

```
ClassiX/
│── app.py              # Main application with routes/controllers - Entry point (Prefered)
│── models.py           # Database models (User, Attendance, etc.)
│── analytics.py        # Attendance analytics & trends
│── utils.py            # Helper functions (QR, notifications, calculations)
│── fingerprint_device.py # Biometric handling
│── config.py           # App configurations
│── extensions.py       # Flask extensions (db, login, mail)
│── requirements.txt    # Python dependencies
│── run.py              # Entry point (But not prefered)
│── static/             # Assets (faq.json, CSS, JS, uploads)
│── templates/          # Jinja2 HTML templates
└── instance/           # SQLite DB (development)
```

---

## 🔧 Configuration / Environment Variables

| Variable             | Description                         |
| -------------------- | ----------------------------------- |
| `SECRET_KEY`         | Flask secret key                    |
| `DATABASE_URL`       | Database URI (SQLite/Postgres)      |
| `MAIL_SERVER`        | SMTP mail server                    |
| `MAIL_USERNAME`      | Email ID for sending notifications  |
| `MAIL_PASSWORD`      | Email password                      |
| `TWILIO_SID`         | Twilio account SID                  |
| `TWILIO_AUTH_TOKEN`  | Twilio auth token                   |
| `QR_EXPIRY`          | QR code expiry time (seconds)       |
| `FINGERPRINT_ENABLE` | Enable/disable fingerprint hardware |

---

## 🤝 Contributing

We welcome contributions!

1. Fork the repo & create a new branch.
2. Make changes with clear commit messages.
3. Submit a pull request with a detailed description.

---

## 🛣️ Roadmap / Future Improvements

* [ ] Windows/macOS/iOS native clients
* [ ] Offline-first version (local data sync when online)
* [ ] AI-driven personalized learning recommendations
* [ ] Gamified attendance leaderboards & rewards
* [ ] Multilingual & low-bandwidth support
* [ ] Accessibility enhancements (speech-to-text, screen reader mode)
* [ ] Enhanced biometric security (liveness detection)
* [ ] Sustainability metrics (eco-savings dashboard)

---

## ❓ FAQ / Troubleshooting

**Q. Why can’t I register directly as a student or teacher?**
➡️ Students/teachers need an admin-generated PIN for secure onboarding.

**Q. My parent is not receiving OTPs.**
➡️ Check email/phone number entered. Resend OTP or contact your teacher/admin.

**Q. Fingerprint/Face recognition isn’t working.**
➡️ Ensure hardware drivers and webcam permissions are enabled. Use fallback QR/manual mode.

**Q. Database errors when running locally?**
➡️ Run `flask db upgrade` to apply migrations. Check your `DATABASE_URL`.

---

## 📜 License

This project is **not open-source**. All rights are reserved by the author.  
You **may not** use, copy, modify, or distribute this project without explicit written permission. Commercial or personal use is **prohibited** unless authorized by the owner.

---

## 🙏 Credits / Acknowledgements

* Built by **Team Classi-X**
* Libraries & services: Flask, SQLAlchemy, Bootstrap, Twilio, OpenCV, NumPy, scikit-learn
