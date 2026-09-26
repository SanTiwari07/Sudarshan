# SUDARSHAN — Production Deployment Guide

> **Classification:** AUTHORITATIVE  

---

## 1. Production Docker Compose Stack

Run with production settings:
```bash
docker compose -f docker-compose.yml up -d
```

### PostgreSQL Activation
In `.env`, set:
```ini
POSTGRES_PASSWORD=<strong password>   # Compose derives DATABASE_URL from it
SUDARSHAN_ENV=production
JWT_SECRET_KEY=<generate_secure_random_hex_64>
ANALYSIS_ENGINE_INTERNAL_TOKEN=<generate_internal_token>
```

---

## 2. Hardened Production Overlay

Deploying with read-only root filesystems and drop-capabilities:
```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d
```
