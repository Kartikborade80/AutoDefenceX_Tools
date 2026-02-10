# AutoDefenceX - Development & Deployment Guide

## 📁 Project Structure

```
AutodefeProject/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── main.py            # Main application entry
│   │   ├── auth.py            # JWT authentication (uses .env)
│   │   ├── database.py        # SQLite/PostgreSQL support (uses .env)
│   │   ├── routers/
│   │   │   ├── chatbot.py     # Gemini AI integration (uses .env)
│   │   └── ...
│   ├── .env                   # Local environment variables (NOT in git)
│   ├── .env.example           # Template for environment variables
│   └── requirements.txt       # Python dependencies
├── frontend/                  # React + Vite frontend
│   ├── src/
│   │   ├── api.js            # API client (uses VITE_API_URL)
│   │   └── components/
│   ├── .env                  # Local environment variables
│   └── .env.production       # Production environment template
├── .gitignore                # Prevents committing secrets
├── DEPLOYMENT.md             # This file
└── run.ps1                   # Local development launcher
```

## 🛠️ Local Development

### Prerequisites
- Python 3.9+
- Node.js 16+
- PowerShell (Windows)

### Quick Start
```powershell
# Clone and setup (if not already done)
cd AutodefeProject

# Ensure .env files exist (already created)
# backend/.env - configured for local development
# frontend/.env - configured for localhost:8000

# Run both servers
.\run.ps1
```

### Manual Start
```powershell
# Backend (Terminal 1)
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (Terminal 2)
cd frontend
npm install
npm run dev
```

Access:
- Frontend: http://localhost:5178
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## 🔐 Environment Variables

### Backend Variables (backend/.env)

All sensitive configuration is now managed through environment variables:

```bash
# Security
SECRET_KEY=<your-jwt-secret>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Database
DATABASE_URL=sqlite:///./autodefencex_v2.db  # Local
# DATABASE_URL=postgresql://user:pass@host/db  # Production

# External APIs
GEMINI_API_KEY=<your-gemini-key>
RESEND_API_KEY=<your-resend-key>

# CORS
ALLOWED_ORIGINS=*  # Local: allow all
# ALLOWED_ORIGINS=https://yourdomain.com  # Production: specific domain
```

### Frontend Variables (frontend/.env)

```bash
# API Configuration
VITE_API_URL=http://localhost:8000  # Local
# VITE_API_URL=https://api.yourdomain.com  # Production

# Branding
VITE_ORG_NAME=AutoDefenceX
```

## 📦 Building for Production

### Backend
```bash
cd backend
pip install -r requirements.txt

# Test production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Build production bundle
npm run build

# Preview production build locally
npm run preview
```

The production build will be in `frontend/dist/`

## 🌐 Deployment Scenarios

### Scenario 1: Separate Frontend + Backend (Recommended)

**Backend → Cloud Run / Render / Railway**
- Deploy backend as API service
- Set environment variables on platform
- Use PostgreSQL database

**Frontend → Vercel / Netlify / Cloudflare Pages**
- Deploy `frontend/dist` as static site
- Set `VITE_API_URL` to backend URL
- Automatic SSL and CDN

### Scenario 2: Monolithic Deployment

Backend serves frontend static files (current setup supports this):
- Build frontend: `npm run build`
- Backend serves from `frontend/dist` automatically
- Deploy entire project to single server

### Scenario 3: Desktop App (Existing)

Your bundled executable approach:
- Uses PyInstaller (`AutoDefenceX.spec`)
- Bundles database with app
- Stores data in `%LOCALAPPDATA%/AutoDefenceX`

## 🔄 Database Migration (SQLite → PostgreSQL)

For production, migrate to PostgreSQL:

1. **Export SQLite data**:
   ```bash
   sqlite3 autodefencex_v2.db .dump > backup.sql
   ```

2. **Set up PostgreSQL**:
   - Cloud SQL (Google Cloud)
   - Managed PostgreSQL (Render, Railway)
   - AWS RDS

3. **Update DATABASE_URL**:
   ```bash
   DATABASE_URL=postgresql://user:password@host:5432/dbname
   ```

4. **Import data** (may need conversion):
   ```bash
   psql $DATABASE_URL < backup.sql
   ```

## 🧪 Testing

### Local Testing
```bash
# Backend
cd backend
pytest  # (if tests exist)

# Frontend
cd frontend
npm run lint
npm run build  # Verify build succeeds
```

### Production Testing Checklist
- [ ] All API endpoints respond correctly
- [ ] Authentication works (login/logout)
- [ ] WebSocket connections stable
- [ ] Chatbot (Gemini AI) responds
- [ ] Email notifications send (if enabled)
- [ ] Multi-tenancy data isolation verified
- [ ] CORS configured correctly
- [ ] SSL/HTTPS working

## 🔒 Security Notes

### ⚠️ IMPORTANT: Before Production Deployment

1. **Revoke exposed API key**:
   - Old Gemini key in code: `AIzaSyA8LdcAaaSBEuGTV6jD4HEvKDSrY8L6TOI`
   - Generate new key: https://aistudio.google.com/apikey

2. **Generate new JWT secret**:
   ```python
   import secrets
   secrets.token_hex(32)
   ```

3. **Restrict CORS**:
   ```bash
   ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
   ```

4. **Verify .env is gitignored**:
   ```bash
   git status  # Should NOT show .env files
   ```

## 📊 Monitoring & Logs

### Development
- Backend logs: Console output
- Frontend logs: Browser DevTools

### Production
- **Sentry**: Error tracking
- **LogRocket**: Session replay
- **Platform logs**: Cloud Run, Render, Railway built-in logs

## 🐛 Common Issues

### Issue: "Module not found: dotenv"
**Solution**: Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Issue: Frontend shows "Network Error"
**Solution**: Check `VITE_API_URL` in `.env`
```bash
# Should match backend URL
VITE_API_URL=http://localhost:8000
```

### Issue: "CORS policy blocked"
**Solution**: Update backend `ALLOWED_ORIGINS`
```bash
# Development: Allow all
ALLOWED_ORIGINS=*

# Production: Specific domain
ALLOWED_ORIGINS=https://yourfrontend.com
```

### Issue: Database locked (SQLite)
**Solution**: Switch to PostgreSQL for production
```bash
DATABASE_URL=postgresql://...
```

## 📚 Additional Documentation

- **Full Deployment Guide**: `deployment_guide.md` (in artifacts)
- **API Documentation**: http://localhost:8000/docs (when running)
- **Implementation Plan**: `implementation_plan.md` (in artifacts)

## 🎯 Deployment Platforms Comparison

| Platform | Backend | Frontend | Database | Difficulty | Cost |
|----------|---------|----------|----------|------------|------|
| **Google Cloud** | Cloud Run | Firebase | Cloud SQL | Medium | Pay-as-go |
| **Render** | Web Service | Static Site | PostgreSQL | Easy | Free tier |
| **Railway** | Service | Service | PostgreSQL | Easy | Trial |
| **Vercel + Render** | Render | Vercel | Render | Easy | Free tier |
| **VPS (DigitalOcean)** | Manual | Manual | Manual | Hard | $5-20/mo |

## 🚀 Recommended First Deployment

**For beginners**: Render.com
1. Free tier available
2. Simple UI
3. Automatic SSL
4. PostgreSQL included
5. Good documentation

**For scalability**: Google Cloud
1. Better integration with Gemini API
2. Auto-scaling
3. Professional features
4. More complex setup

---

**Questions?** Check the full `deployment_guide.md` in the artifacts folder or refer to the troubleshooting section above.
