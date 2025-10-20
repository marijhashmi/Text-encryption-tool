# 🔐 Web-Based Text Encryption Tool

A **Flask-based web application** that allows users to encrypt and decrypt text using multiple algorithms, including **Caesar Cipher, AES, and base64**.
The app provides a simple and secure interface for testing encryption techniques.

---

## 🚀 Features

* Encrypt and decrypt plain text using selected algorithms.
* Supports **Caesar Cipher**, **AES**, and **base64**.
* Option to **copy ciphertext** easily.
* Basic **input validation** (no empty inputs, must select algorithm).
* Built with a **responsive UI** for easy use.
* Secure message handling using **Flask backend**.

---

## 🧩 Tech Stack

**Frontend:** HTML, CSS, JavaScript
**Backend:** Python (Flask)
**Database:** SQLite (Flask SQLAlchemy)
**Encryption Library:** PyCryptodome

---

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/web-encryption-tool.git
cd web-encryption-tool
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Environment

* **Windows**

  ```bash
  .venv\Scripts\activate
  ```
* **Mac/Linux**

  ```bash
  source .venv/bin/activate
  ```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python backend/app.py
```

Then open your browser and visit:

```
http://127.0.0.1:5000
```

---

## 🔒 Encryption Algorithms Implemented

| Algorithm                              | Description                             | Supports Decryption |
| -------------------------------------- | --------------------------------------- | ------------------- |
| **Caesar Cipher**                      | Shifts each character by a fixed key    | ✅ Yes               |
| **AES (Advanced Encryption Standard)** | Symmetric encryption using a secret key | ✅ Yes               |
| **base64**                            | Encodes text to ASCII format         |  ✅ Yes  |

---


## 💡 Future Enhancements

* Add user authentication to save encrypted messages.
* Include more encryption methods (e.g., RSA, DES).
* Create a React-based frontend for dynamic interaction.

---

## 🧑‍💻 Author

**Muhammad Marij Younas**
📍 Lahore, Pakistan
📧 [marijhashmi777@gmail.com](mailto:marijhashmi777@gmail.com)
🔗 [LinkedIn](https://www.linkedin.com/in/muhammad-marij-younas-a60a33291)
🔗 [GitHub](https://github.com/dashboard)

