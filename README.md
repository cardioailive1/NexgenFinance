# NexGen Finance

**AI-powered financial analysis platform by Corverxis Technologies.**  
Financial Statements · Accounting · Audit · Market Analysis · Trading Agent

---

## Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 20 |
| Framework | Express 4 |
| ORM | Prisma 5 + PostgreSQL |
| AI | Anthropic Claude (claude-sonnet-4-6) |
| Auth | OAuth2 (Google / GitHub / Microsoft) + JWT |
| Frontend | Vanilla JS SPA served as static files |
| Deployment | Render.com |

---

## Project Structure

```
nexgen-finance/
├── src/
│   ├── backend/
│   │   ├── config/          # Prisma, Passport, app config
│   │   ├── controllers/     # Auth, Reports, Privacy
│   │   ├── middleware/      # Auth, Security, Rate limiting
│   │   ├── routes/          # Express routers
│   │   ├── services/        # Anthropic, Encryption, Audit
│   │   ├── utils/           # Logger
│   │   └── server.js        # Entry point
│   └── frontend/
│       └── public/          # Static SPA + auth page
├── prisma/
│   ├── schema.prisma        # Full data model
│   └── seed.js
├── .github/workflows/       # CI/CD
├── render.yaml              # Render.com deployment
├── Dockerfile               # Container build
├── docker-compose.yml       # Local development
└── .env.example
```

---

## Quick Start — Local Development

### Prerequisites
- Node.js 20+
- PostgreSQL 15+ (or Docker)
- Anthropic API key
- OAuth2 app credentials (at least one provider)

### 1. Clone & install
```bash
git clone https://github.com/corverxis/nexgen-finance.git
cd nexgen-finance
npm install
```

### 2. Environment
```bash
cp .env.example .env
# Edit .env — fill in all required values
```

**Generate secrets:**
```bash
# JWT secrets (run twice for access + refresh)
openssl rand -hex 64

# Encryption key (exactly 32 bytes = 64 hex chars)
openssl rand -hex 32
```

### 3. Database
```bash
# Start Postgres (Docker)
docker-compose up db -d

# Apply migrations
npx prisma migrate dev --name init

# Seed config defaults
npm run prisma:seed
```

### 4. Register OAuth2 apps

| Provider | Registration URL | Callback URL |
|---|---|---|
| Google | https://console.cloud.google.com/apis/credentials | `http://localhost:10000/api/auth/google/callback` |
| GitHub | https://github.com/settings/applications/new | `http://localhost:10000/api/auth/github/callback` |
| Microsoft | https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps | `http://localhost:10000/api/auth/microsoft/callback` |

Fill the client IDs and secrets into `.env`.

### 5. Run
```bash
npm run dev
# → http://localhost:10000
```

---

## Deploy to Render.com

### 1. Push to GitHub
```bash
git remote add origin https://github.com/your-org/nexgen-finance.git
git push -u origin main
```

### 2. Connect to Render
1. Log in at https://render.com
2. **New → Blueprint** → select your repo
3. Render detects `render.yaml` and creates the web service + database automatically

### 3. Set secret environment variables in Render dashboard

| Variable | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic key |
| `ENCRYPTION_KEY` | 64-char hex string (`openssl rand -hex 32`) |
| `GOOGLE_CLIENT_ID` | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | From Google Cloud Console |
| `GOOGLE_CALLBACK_URL` | `https://your-app.onrender.com/api/auth/google/callback` |
| `GITHUB_CLIENT_ID` | From GitHub OAuth app |
| `GITHUB_CLIENT_SECRET` | From GitHub OAuth app |
| `GITHUB_CALLBACK_URL` | `https://your-app.onrender.com/api/auth/github/callback` |
| `MICROSOFT_CLIENT_ID` | From Azure App Registration |
| `MICROSOFT_CLIENT_SECRET` | From Azure App Registration |
| `MICROSOFT_CALLBACK_URL` | `https://your-app.onrender.com/api/auth/microsoft/callback` |

### 4. First deploy — run migrations
In Render dashboard → your service → **Shell**:
```bash
npx prisma migrate deploy
npm run prisma:seed
```

### 5. Update OAuth redirect URIs
Update each OAuth app's allowed callback URLs to your live Render URL.

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/auth/google` | Initiate Google OAuth2 |
| GET | `/api/auth/github` | Initiate GitHub OAuth2 |
| GET | `/api/auth/microsoft` | Initiate Microsoft OAuth2 |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Revoke current session |
| POST | `/api/auth/logout/all` | Revoke all sessions |
| GET | `/api/auth/me` | Current user profile |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/reports/generate` | Generate AI report |
| GET | `/api/reports` | List user reports |
| GET | `/api/reports/:id` | Get report (decrypted) |
| DELETE | `/api/reports/:id` | Delete (SEC retention enforced) |

**POST `/api/reports/generate` body:**
```json
{
  "module": "TRADING",
  "reportType": "equityforecast",
  "prompt": "Analyse Apple (AAPL) for a swing trade...",
  "inputData": { "symbol": "AAPL", "timeframe": "Swing" }
}
```

### Privacy & Compliance (GDPR/CCPA)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/privacy/policy` | Machine-readable policy metadata |
| POST | `/api/privacy/consent` | Record consent |
| POST | `/api/privacy/export` | Request data export (Art. 20) |
| POST | `/api/privacy/delete` | Request account deletion (Art. 17) |

### System
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/ready` | Readiness probe (checks DB) |
| GET | `/api/compliance/status` | Compliance posture |

---

## Compliance

### SOC 2 Type II
- **CC6** — Logical & physical access controls (JWT, OAuth2, RBAC, HttpOnly cookies)
- **CC7** — System monitoring (structured logging, request correlation IDs)
- **CC9** — Risk mitigation (rate limiting, input validation, tamper-evident audit trail)
- Audit logs retained 7 years with SHA-256 chained integrity

### SEC Rule 17a-4
- Financial reports encrypted and retained for 7 years
- Tamper-evident content hash on every report
- Deletion blocked within retention window
- Audit trail of all report access

### GDPR (EU) / UK GDPR
- Article 5  — Lawfulness, fairness, transparency
- Article 6  — Legal basis (consent + contract)
- Article 7  — Consent management with version tracking
- Article 17 — Right to erasure (with SEC retention override)
- Article 20 — Right to data portability (JSON export)
- Article 25 — Privacy by design (encryption, data minimisation)
- Article 32 — Security of processing (AES-256-GCM, TLS 1.3)

### CCPA
- §1798.100 — Right to know / data export
- §1798.105 — Right to delete
- §1798.120 — Right to opt-out (marketing)

---

## License

Copyright © 2025 Corverxis Technologies Ltd. All rights reserved.
