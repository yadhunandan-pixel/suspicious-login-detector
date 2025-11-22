# 🔐 Suspicious Login Detector  
A lightweight **Spring Boot + JavaScript** web application that analyzes login activity logs and detects suspicious user login patterns such as:

- Multiple consecutive failed logins  
- Unknown or unusual IP addresses  
- Login attempts from new devices  
- Abnormal timings  
- High-frequency login bursts  

This tool helps identify possible **brute-force attacks**, **credential stuffing**, or **unauthorized access attempts** from simple CSV logs.

---

## 🚀 Features  
- 📤 Upload CSV logs directly from browser  
- ⚡ Real-time analysis using Java + Spring Boot  
- 📊 Calculates risk score per IP & username  
- 🛑 Highlights suspicious activity  
- 🌐 Clean HTML/CSS/JS frontend (no frameworks)  
- 💡 Simple, beginner-friendly cybersecurity project  
- 📁 Works entirely offline  

---

## 📂 Tech Stack  
**Backend:**  
- Java 17  
- Spring Boot 3  
- REST API  

**Frontend:**  
- HTML5  
- CSS3  
- Vanilla JavaScript  

---

## 📁 CSV Format  
Your CSV file must follow this header format:  

