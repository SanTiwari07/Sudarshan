# SUDARSHAN — Local Development Guide

> **Classification:** AUTHORITATIVE  

---

## 1. Local Environment Setup

1. **Python 3.11+ Virtual Environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r backend/requirements.txt -r shared/requirements.txt
   ```
2. **Frontend Setup (Node.js 18+):**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
3. **Environment File:**
   Copy `.env.example` to `.env` and configure `JWT_SECRET_KEY`.
