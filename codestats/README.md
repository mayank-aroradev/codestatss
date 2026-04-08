# CodeStats 🚀

A full-stack Flask web app to track your DSA coding practice — with auth, analytics, spaced repetition, AI coaching, and import/export.

## What's New (v2)

| Feature | Details |
|---|---|
| 🔒 **Security** | Rate limiting on auth routes, enforced env-var SECRET_KEY in prod, URL sanitization, password length validation, email normalization |
| 🔐 **Sessions** | Persistent 30-day sessions with `HttpOnly` + `SameSite=Lax` cookie flags |
| 🗄 **PostgreSQL** | Auto-detects `DATABASE_URL` env var — SQLite for dev, Postgres for prod |
| ♻ **Spaced Repetition** | Review queue with 1→3→7→14→30→60 day intervals; badge shows due count |
| 💾 **Solution Code** | Save and view your code solution per problem |
| 🏷 **Tags** | Comma-separated tags per problem; searchable |
| 📊 **Daily Goal** | Set your daily target; sidebar shows live progress bar |
| ✏ **Edit UI** | Full edit modal (was missing from v1) |
| 📤 **Export** | Download CSV or JSON from profile modal |
| 📥 **Import** | Upload CSV or JSON to bulk-import problems |
| 📑 **Pagination** | `/api/problems?page=N&per_page=50` for large collections |
| ⚙ **Blueprints-ready** | Logic cleanly separated; easy to split into blueprints |

## Project Structure

```
codestats/
├── app.py              ← Flask app, models, all routes
├── requirements.txt    ← Python deps
├── Procfile            ← gunicorn start command
├── static/
│   └── manifest.json   ← PWA manifest
└── templates/
    ├── base.html       ← Sidebar, daily goal, profile modal
    ├── login.html      ← Auth page
    ├── dashboard.html  ← Heatmap, metrics, recent problems
    ├── tracker.html    ← Log + edit + import + search
    ├── review.html     ← Spaced repetition review queue ← NEW
    ├── analytics.html  ← Deep analytics
    ├── platforms.html  ← Platform breakdown
    └── ai_coach.html   ← AI-powered coaching
```

## Local Setup

```bash
cd codestats
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | **Yes (prod)** | random (dev) | Flask session signing key |
| `DATABASE_URL` | No | `sqlite:///codestats.db` | Postgres URL for production |
| `ANTHROPIC_API_KEY` | No | — | Enables live AI coaching |
| `FLASK_ENV` | No | development | Set to `production` to enforce SECRET_KEY |

## Deploy to Render (Free)

1. Push to GitHub
2. New Web Service → connect repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add env vars: `SECRET_KEY`, `DATABASE_URL` (from Render Postgres), optionally `ANTHROPIC_API_KEY`
6. Deploy!

## Deploy to Railway

```bash
railway login && railway init && railway up
# Set env vars in Railway dashboard
```

## API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/api/problems` | All problems (add `?page=N&per_page=50` to paginate) |
| POST | `/api/problems` | Add problem |
| PUT | `/api/problems/:id` | Edit problem |
| DELETE | `/api/problems/:id` | Delete problem |
| GET | `/api/review-due` | Problems due for review today |
| POST | `/api/problems/:id/review` | Mark reviewed `{remembered: true/false}` |
| GET | `/api/analytics` | Full analytics payload |
| GET | `/api/daily-progress` | Today's goal progress |
| GET | `/api/export/csv` | Download CSV export |
| GET | `/api/export/json` | Download JSON export |
| POST | `/api/import` | Import CSV or JSON file |
| GET/PUT | `/api/profile` | Get/update user profile |
| POST | `/api/ai-coach` | Get AI coaching `{type: full/roadmap/gaps}` |

## Database Models

**users**: id, username, email, password_hash, leetcode_handle, daily_goal, created_at

**userdata**: id, user_id (FK), question_name, topic, difficulty, platform, language, time_minutes, times_done, question_link, solved, notes, **solution_code**, **tags**, **review_date**, **review_interval**, created_at
