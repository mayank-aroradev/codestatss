from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from functools import wraps
import json, os, re, urllib.request, urllib.parse, secrets, csv, io

app = Flask(__name__)

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY = 'mysupersecretkey123'
if not SECRET_KEY:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError("SECRET_KEY environment variable must be set in production!")
    SECRET_KEY = secrets.token_hex(32)  # random per-process in dev

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///codestats.db')
# Fix for Heroku/Render Postgres URLs (postgres:// → postgresql://)
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

db = SQLAlchemy(app)

# ── Rate limiting (simple in-memory) ──────────────────────────────────────────
_rate_store = {}  # ip -> [timestamps]

def rate_limit(max_calls=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            now = datetime.utcnow().timestamp()
            hits = [t for t in _rate_store.get(ip, []) if now - t < window]
            if len(hits) >= max_calls:
                return jsonify({'success': False, 'error': 'Too many attempts. Please wait.'}), 429
            hits.append(now)
            _rate_store[ip] = hits
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)
    leetcode_handle = db.Column(db.String(80), nullable=True)
    daily_goal      = db.Column(db.Integer, default=3)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    problems        = db.relationship('UserData', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)
    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class UserData(db.Model):
    __tablename__ = 'userdata'
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    question_name = db.Column(db.String(200), nullable=False)
    topic         = db.Column(db.String(100), nullable=False)
    difficulty    = db.Column(db.String(20), nullable=False)
    platform      = db.Column(db.String(50), nullable=False, default='LeetCode')
    language      = db.Column(db.String(50), nullable=False, default='Python')
    time_minutes  = db.Column(db.Float, nullable=False)
    times_done    = db.Column(db.Integer, default=1)
    question_link = db.Column(db.String(500), nullable=True)
    solved        = db.Column(db.Boolean, default=True)
    notes         = db.Column(db.Text, nullable=True)
    solution_code = db.Column(db.Text, nullable=True)      # NEW: store solution snippet
    tags          = db.Column(db.String(300), nullable=True)  # NEW: comma-separated tags
    review_date   = db.Column(db.Date, nullable=True)      # NEW: spaced repetition date
    review_interval = db.Column(db.Integer, default=0)     # NEW: days until next review
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'question_name': self.question_name,
            'topic': self.topic,
            'difficulty': self.difficulty,
            'platform': self.platform,
            'language': self.language,
            'time_minutes': self.time_minutes,
            'times_done': self.times_done,
            'question_link': self.question_link,
            'solved': self.solved,
            'notes': self.notes,
            'solution_code': self.solution_code,
            'tags': self.tags or '',
            'review_date': self.review_date.isoformat() if self.review_date else None,
            'review_interval': self.review_interval,
            'created_at': self.created_at.strftime('%Y-%m-%d'),
        }

# ── Auth helpers ──────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def sanitize_url(url):
    """Only allow http/https URLs."""
    if not url:
        return None
    url = url.strip()
    if url and not re.match(r'^https?://', url, re.IGNORECASE):
        return None
    return url[:500]

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_calls=20, window=60)
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        d = request.get_json() if request.is_json else request.form
        user = User.query.filter_by(email=d.get('email', '').strip().lower()).first()
        if user and user.check_password(d.get('password', '')):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            if request.is_json:
                return jsonify({'success': True})
        else:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_calls=10, window=300)
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        d = request.get_json() if request.is_json else request.form
        username = d.get('username', '').strip()
        email = d.get('email', '').strip().lower()
        password = d.get('password', '')
        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return jsonify({'success': False, 'error': 'Username: letters, numbers, _ . - only'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 409
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already taken'}), 409
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        if request.is_json:
            return jsonify({'success': True})
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/tracker')
@login_required
def tracker():
    return render_template('tracker.html', username=session['username'])

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html', username=session['username'])

@app.route('/platforms')
@login_required
def platforms():
    return render_template('platforms.html', username=session['username'])

@app.route('/ai-coach')
@login_required
def ai_coach():
    return render_template('ai_coach.html', username=session['username'])

@app.route('/review')
@login_required
def review():
    return render_template('review.html', username=session['username'])

# ── Problems API ──────────────────────────────────────────────────────────────
@app.route('/api/problems', methods=['GET'])
@login_required
def get_problems():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 0, type=int)  # 0 = all
    
    q = UserData.query.filter_by(user_id=session['user_id']).order_by(UserData.created_at.desc())
    
    if per_page > 0:
        paginated = q.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'problems': [p.to_dict() for p in paginated.items],
            'total': paginated.total,
            'pages': paginated.pages,
            'page': page,
        })
    
    return jsonify([p.to_dict() for p in q.all()])


@app.route('/api/problems', methods=['POST'])
@login_required
def add_problem():
    d = request.get_json()
    if not d:
        return jsonify({'error': 'No data'}), 400

    name = d.get('question_name', '').strip()[:200]
    topic = d.get('topic', '').strip()[:100]
    if not name or not topic:
        return jsonify({'error': 'Name and topic required'}), 400

    try:
        time_minutes = float(d.get('time_minutes', 0))
        times_done = int(d.get('times_done', 1))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid numeric field'}), 400

    # Spaced repetition: first review in 1 day
    review_date = date.today() + timedelta(days=1) if d.get('solved') else None

    p = UserData(
        user_id=session['user_id'],
        question_name=name,
        topic=topic,
        difficulty=d.get('difficulty', 'Medium') if d.get('difficulty') in ('Easy', 'Medium', 'Hard') else 'Medium',
        platform=d.get('platform', 'LeetCode')[:50],
        language=d.get('language', 'Python')[:50],
        time_minutes=max(0, time_minutes),
        times_done=max(1, times_done),
        question_link=sanitize_url(d.get('question_link', '')),
        solved=bool(d.get('solved', True)),
        notes=d.get('notes', '').strip()[:2000] or None,
        solution_code=d.get('solution_code', '').strip() or None,
        tags=','.join(t.strip()[:30] for t in d.get('tags', '').split(',') if t.strip())[:300] or None,
        review_date=review_date,
        review_interval=1,
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'success': True, 'id': p.id})


@app.route('/api/problems/<int:pid>', methods=['DELETE'])
@login_required
def delete_problem(pid):
    p = UserData.query.filter_by(id=pid, user_id=session['user_id']).first_or_404()
    db.session.delete(p)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/problems/<int:pid>', methods=['PUT'])
@login_required
def update_problem(pid):
    p = UserData.query.filter_by(id=pid, user_id=session['user_id']).first_or_404()
    d = request.get_json()
    if not d:
        return jsonify({'error': 'No data'}), 400

    if 'question_name' in d:
        p.question_name = d['question_name'].strip()[:200]
    if 'topic' in d:
        p.topic = d['topic'].strip()[:100]
    if 'difficulty' in d and d['difficulty'] in ('Easy', 'Medium', 'Hard'):
        p.difficulty = d['difficulty']
    if 'platform' in d:
        p.platform = d['platform'][:50]
    if 'language' in d:
        p.language = d['language'][:50]
    if 'question_link' in d:
        p.question_link = sanitize_url(d['question_link'])
    if 'notes' in d:
        p.notes = d['notes'].strip()[:2000] or None
    if 'solution_code' in d:
        p.solution_code = d['solution_code'].strip() or None
    if 'tags' in d:
        p.tags = ','.join(t.strip()[:30] for t in d['tags'].split(',') if t.strip())[:300] or None
    if 'time_minutes' in d:
        p.time_minutes = max(0, float(d['time_minutes']))
    if 'times_done' in d:
        p.times_done = max(1, int(d['times_done']))
    if 'solved' in d:
        p.solved = bool(d['solved'])

    db.session.commit()
    return jsonify({'success': True})


# ── Spaced Repetition ─────────────────────────────────────────────────────────
REVIEW_INTERVALS = [1, 3, 7, 14, 30, 60]  # days

@app.route('/api/review-due', methods=['GET'])
@login_required
def get_review_due():
    today = date.today()
    due = UserData.query.filter(
        UserData.user_id == session['user_id'],
        UserData.solved == True,
        UserData.review_date <= today,
        UserData.review_date != None,
    ).order_by(UserData.review_date).limit(20).all()
    return jsonify([p.to_dict() for p in due])


@app.route('/api/problems/<int:pid>/review', methods=['POST'])
@login_required
def mark_reviewed(pid):
    p = UserData.query.filter_by(id=pid, user_id=session['user_id']).first_or_404()
    d = request.get_json() or {}
    remembered = d.get('remembered', True)

    if remembered:
        # Advance interval
        next_idx = min(p.review_interval, len(REVIEW_INTERVALS) - 1)
        days = REVIEW_INTERVALS[next_idx]
        p.review_interval = min(next_idx + 1, len(REVIEW_INTERVALS) - 1)
    else:
        # Reset
        days = 1
        p.review_interval = 0

    p.review_date = date.today() + timedelta(days=days)
    db.session.commit()
    return jsonify({'success': True, 'next_review': p.review_date.isoformat()})


# ── Export / Import ───────────────────────────────────────────────────────────
@app.route('/api/export/csv')
@login_required
def export_csv():
    probs = UserData.query.filter_by(user_id=session['user_id']).order_by(UserData.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'id', 'question_name', 'topic', 'difficulty', 'platform', 'language',
        'time_minutes', 'times_done', 'question_link', 'solved', 'notes',
        'solution_code', 'tags', 'review_date', 'created_at'
    ])
    writer.writeheader()
    for p in probs:
        writer.writerow({
            'id': p.id, 'question_name': p.question_name, 'topic': p.topic,
            'difficulty': p.difficulty, 'platform': p.platform, 'language': p.language,
            'time_minutes': p.time_minutes, 'times_done': p.times_done,
            'question_link': p.question_link or '', 'solved': p.solved,
            'notes': p.notes or '', 'solution_code': p.solution_code or '',
            'tags': p.tags or '', 'review_date': p.review_date.isoformat() if p.review_date else '',
            'created_at': p.created_at.strftime('%Y-%m-%d'),
        })
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename=codestats_export_{date.today()}.csv'
    return resp


@app.route('/api/export/json')
@login_required
def export_json():
    probs = UserData.query.filter_by(user_id=session['user_id']).order_by(UserData.created_at.desc()).all()
    resp = make_response(json.dumps([p.to_dict() for p in probs], indent=2))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Content-Disposition'] = f'attachment; filename=codestats_export_{date.today()}.json'
    return resp


@app.route('/api/import', methods=['POST'])
@login_required
def import_problems():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400

    try:
        content = f.read().decode('utf-8')
        if f.filename.endswith('.json'):
            rows = json.loads(content)
        elif f.filename.endswith('.csv'):
            reader = csv.DictReader(io.StringIO(content))
            rows = list(reader)
        else:
            return jsonify({'error': 'Only CSV or JSON files supported'}), 400
    except Exception as e:
        return jsonify({'error': f'Parse error: {e}'}), 400

    imported = 0
    for row in rows:
        name = str(row.get('question_name', '')).strip()[:200]
        topic = str(row.get('topic', '')).strip()[:100]
        if not name or not topic:
            continue
        p = UserData(
            user_id=session['user_id'],
            question_name=name, topic=topic,
            difficulty=row.get('difficulty', 'Medium') if row.get('difficulty') in ('Easy', 'Medium', 'Hard') else 'Medium',
            platform=str(row.get('platform', 'LeetCode'))[:50],
            language=str(row.get('language', 'Python'))[:50],
            time_minutes=max(0, float(row.get('time_minutes') or 0)),
            times_done=max(1, int(row.get('times_done') or 1)),
            question_link=sanitize_url(str(row.get('question_link', ''))),
            solved=str(row.get('solved', 'True')).lower() in ('true', '1', 'yes'),
            notes=str(row.get('notes', '')).strip()[:2000] or None,
            solution_code=str(row.get('solution_code', '')).strip() or None,
            tags=str(row.get('tags', '')).strip()[:300] or None,
        )
        db.session.add(p)
        imported += 1

    db.session.commit()
    return jsonify({'success': True, 'imported': imported})


# ── Daily Goal ────────────────────────────────────────────────────────────────
@app.route('/api/daily-progress')
@login_required
def daily_progress():
    user = User.query.get(session['user_id'])
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    count = UserData.query.filter(
        UserData.user_id == session['user_id'],
        UserData.created_at >= today_start,
    ).count()
    return jsonify({
        'done': count,
        'goal': user.daily_goal or 3,
        'pct': min(100, round(count / (user.daily_goal or 3) * 100)),
    })


@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    user = User.query.get(session['user_id'])
    return jsonify({
        'username': user.username,
        'email': user.email,
        'leetcode_handle': user.leetcode_handle or '',
        'daily_goal': user.daily_goal or 3,
    })


@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    d = request.get_json()
    user = User.query.get(session['user_id'])
    if 'leetcode_handle' in d:
        user.leetcode_handle = d['leetcode_handle'][:80]
    if 'daily_goal' in d:
        try:
            user.daily_goal = max(1, min(50, int(d['daily_goal'])))
        except (ValueError, TypeError):
            pass
    db.session.commit()
    return jsonify({'success': True})


# ── URL extraction ────────────────────────────────────────────────────────────
PLATFORM_PATTERNS = {
    'leetcode.com': 'LeetCode', 'hackerrank.com': 'HackerRank',
    'codeforces.com': 'Codeforces', 'codechef.com': 'CodeChef',
    'geeksforgeeks.org': 'GeeksForGeeks', 'interviewbit.com': 'InterviewBit',
    'atcoder.jp': 'AtCoder', 'spoj.com': 'SPOJ',
}
TOPIC_KEYWORDS = {
    'array': 'Arrays', 'string': 'Strings', 'tree': 'Trees', 'graph': 'Graphs',
    'dp': 'Dynamic Programming', 'dynamic': 'Dynamic Programming',
    'linked': 'Linked Lists', 'hash': 'Hash Maps', 'heap': 'Heaps',
    'stack': 'Stacks', 'queue': 'Queues', 'binary': 'Binary Search',
    'sort': 'Sorting', 'greedy': 'Greedy', 'backtrack': 'Backtracking',
    'trie': 'Tries', 'math': 'Math', 'bit': 'Bit Manipulation',
    'two-pointer': 'Two Pointers', 'sliding': 'Sliding Window',
    'prefix': 'Prefix Sum', 'union': 'Union Find',
}

def detect_platform(url):
    for domain, name in PLATFORM_PATTERNS.items():
        if domain in url: return name
    return 'Other'

def extract_slug(url):
    m = re.search(r'/problems/([^/?#]+)', url)
    if m: return m.group(1)
    m = re.search(r'/challenges/([^/?#]+)', url)
    if m: return m.group(1)
    parts = [p for p in url.rstrip('/').split('/') if p and not p.startswith('http') and '.' not in p]
    return parts[-1] if parts else ''

def slug_to_name(slug):
    return ' '.join(w.capitalize() for w in re.split(r'[-_]', slug) if w)

def guess_topic(text):
    for kw, topic in TOPIC_KEYWORDS.items():
        if kw in text: return topic
    return ''

@app.route('/api/extract-problem')
@login_required
def extract_problem():
    url = request.args.get('url', '').strip()
    if not url or not re.match(r'^https?://', url):
        return jsonify({'error': 'Invalid URL'}), 400

    platform = detect_platform(url)
    slug = extract_slug(url)
    name = slug_to_name(slug)
    topic = guess_topic(name.lower() + ' ' + url.lower())
    diff = 'Medium'

    if 'leetcode.com' in url and slug:
        try:
            query = json.dumps({
                "query": "query q($s:String!){question(titleSlug:$s){title difficulty topicTags{name}}}",
                "variables": {"s": slug}
            }).encode()
            req = urllib.request.Request(
                'https://leetcode.com/graphql', data=query,
                headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0',
                         'Referer': 'https://leetcode.com'}, method='POST'
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read())
            q = data.get('data', {}).get('question', {})
            if q and q.get('title'):
                name = q['title']
                diff = q.get('difficulty', 'Medium').capitalize()
                for tag in (q.get('topicTags') or []):
                    m = guess_topic(tag['name'].lower())
                    if m: topic = m; break
                if not topic and q.get('topicTags'):
                    topic = q['topicTags'][0]['name']
        except Exception:
            pass

    return jsonify({'question_name': name, 'platform': platform, 'difficulty': diff, 'topic': topic, 'slug': slug})


# ── Analytics ─────────────────────────────────────────────────────────────────
def build_analytics(uid):
    problems = UserData.query.filter_by(user_id=uid).all()
    if not problems:
        return {'empty': True}

    total = len(problems)
    solved_cnt = sum(1 for p in problems if p.solved)
    total_time = sum(p.time_minutes for p in problems)

    topic_map = {}
    for p in problems:
        t = p.topic
        if t not in topic_map:
            topic_map[t] = {'total': 0, 'solved': 0, 'total_time': 0, 'times': []}
        topic_map[t]['total'] += 1
        if p.solved:
            topic_map[t]['solved'] += 1
            topic_map[t]['total_time'] += p.time_minutes
            topic_map[t]['times'].append(p.time_minutes)

    topic_stats = []
    for t, d in topic_map.items():
        sr = d['solved'] / d['total'] if d['total'] else 0
        avg = round(d['total_time'] / d['solved'], 1) if d['solved'] else 0
        topic_stats.append({
            'topic': t, 'total': d['total'], 'solved': d['solved'],
            'avg_time': avg, 'weakness': round((1 - sr) + (avg / 100), 3), 'pct': round(sr * 100)
        })
    topic_stats.sort(key=lambda x: -x['weakness'])

    diff_map = {'Easy': 0, 'Medium': 0, 'Hard': 0}
    for p in problems:
        diff_map[p.difficulty] = diff_map.get(p.difficulty, 0) + 1

    today = datetime.utcnow().date()
    daily = {}
    for p in problems:
        day = p.created_at.date().isoformat()
        daily[day] = daily.get(day, 0) + 1

    heatmap = [{'date': (today - timedelta(days=i)).isoformat(),
                'count': daily.get((today - timedelta(days=i)).isoformat(), 0)}
               for i in range(364, -1, -1)]
    recent = [{'date': (today - timedelta(days=i)).isoformat(),
               'count': daily.get((today - timedelta(days=i)).isoformat(), 0)}
              for i in range(6, -1, -1)]

    streak, cur = 0, today
    while cur.isoformat() in daily:
        streak += 1
        cur -= timedelta(days=1)

    platform_map = {}
    for p in problems:
        pl = p.platform or 'Other'
        if pl not in platform_map:
            platform_map[pl] = {'total': 0, 'solved': 0, 'Easy': 0, 'Medium': 0, 'Hard': 0, 'languages': {}}
        platform_map[pl]['total'] += 1
        if p.solved: platform_map[pl]['solved'] += 1
        platform_map[pl][p.difficulty] = platform_map[pl].get(p.difficulty, 0) + 1
        lang = p.language or 'Other'
        platform_map[pl]['languages'][lang] = platform_map[pl]['languages'].get(lang, 0) + 1

    platform_stats = [{'platform': pl, 'total': d['total'], 'solved': d['solved'],
                        'Easy': d['Easy'], 'Medium': d['Medium'], 'Hard': d['Hard'],
                        'languages': d['languages']}
                       for pl, d in platform_map.items()]
    platform_stats.sort(key=lambda x: -x['total'])

    lang_map = {}
    for p in problems:
        lang_map[p.language or 'Other'] = lang_map.get(p.language or 'Other', 0) + 1

    # Time-to-solve trend: last 8 weeks avg per week
    weekly_time = {}
    for p in problems:
        if p.solved:
            wk = (today - p.created_at.date()).days // 7
            if wk < 8:
                if wk not in weekly_time: weekly_time[wk] = []
                weekly_time[wk].append(p.time_minutes)
    time_trend = [{'week': f'-{w}w', 'avg': round(sum(t)/len(t), 1)}
                  for w, t in sorted(weekly_time.items()) if t]

    # Due for review today
    due_count = UserData.query.filter(
        UserData.user_id == uid,
        UserData.solved == True,
        UserData.review_date <= today,
        UserData.review_date != None,
    ).count()

    return {
        'empty': False, 'total': total, 'solved': solved_cnt,
        'unsolved': total - solved_cnt, 'total_time': round(total_time, 1),
        'streak': streak, 'topic_stats': topic_stats, 'diff_map': diff_map,
        'heatmap': heatmap, 'recent': recent, 'weak_topics': topic_stats[:3],
        'platform_stats': platform_stats, 'lang_map': lang_map,
        'time_trend': time_trend, 'due_review': due_count,
    }


@app.route('/api/analytics')
@login_required
def get_analytics():
    return jsonify(build_analytics(session['user_id']))


# ── AI Coach ──────────────────────────────────────────────────────────────────
@app.route('/api/ai-coach', methods=['POST'])
@login_required
@rate_limit(max_calls=15, window=300)
def ai_coach_api():
    data = build_analytics(session['user_id'])
    username = session['username']
    req_type = (request.get_json() or {}).get('type', 'full')

    if data.get('empty'):
        return jsonify({'result': "Log some problems first — I'll give personalized coaching once I have data to analyze!"})

    topics_summary = ', '.join([f"{t['topic']} ({t['solved']}/{t['total']}, {t['pct']}%)" for t in data['topic_stats'][:10]])
    weak_summary = ', '.join([f"{t['topic']} (score:{t['weakness']})" for t in data['weak_topics']])
    diff_summary = f"Easy:{data['diff_map']['Easy']} Medium:{data['diff_map']['Medium']} Hard:{data['diff_map']['Hard']}"
    total = data['total']
    solve_rate = round(data['solved'] / data['total'] * 100) if data['total'] else 0
    platform_summary = ', '.join([f"{p['platform']}:{p['total']}" for p in data['platform_stats']])

    prompts = {
        'full': f"""You are CodeStats AI Coach — expert DSA mentor. Analyze this coder and give a comprehensive personalized report.
User: {username} | Problems: {total} | Solve Rate: {solve_rate}% | Streak: {data['streak']} days
Difficulty: {diff_summary} | Platforms: {platform_summary}
Topics: {topics_summary}
Weakest: {weak_summary}

Write a detailed analysis with these sections using markdown headers:
## 🎯 Skill Assessment
## 📊 Weakness Mapping & Pattern Insights  
## 🗺️ 30-Day Personalized Roadmap
## 🔮 Next 5 Recommended Topics (with reasoning)
## ⚡ Predictive Skill Gap Analysis
## 💡 3 Actionable Tips

Be specific, data-driven, and encouraging. Reference their actual numbers.""",
        'roadmap': f"""Create a 30-day DSA roadmap for {username}. Stats: {total} problems, {solve_rate}% solve rate. Weaknesses: {weak_summary}. Topics done: {topics_summary}.
Give week-by-week plan with specific topics, problem counts, and resources. Use markdown.""",
        'gaps': f"""Skill gap analysis for {username}. Topics: {topics_summary}. Weaknesses: {weak_summary}. Difficulty: {diff_summary}.
Identify critical interview gaps, almost-mastered topics, and blind spots. Be specific. Use markdown.""",
    }
    prompt = prompts.get(req_type, prompts['full'])

    if not ANTHROPIC_API_KEY:
        level = 'Beginner' if total < 30 else 'Intermediate' if total < 100 else 'Advanced'
        weak_list = [t['topic'] for t in data['weak_topics']]
        result = f"""## 🎯 Skill Assessment\nYou're at **{level}** level with {total} problems and {solve_rate}% solve rate.\n\n## 📊 Weakness Mapping\nYour weakest topics are **{', '.join(weak_list) if weak_list else 'not yet determined'}**.\n\n## 🗺️ 30-Day Roadmap\n**Week 1:** {weak_list[0] if weak_list else 'Arrays'} — 3 Easy + 1 Medium daily\n**Week 2:** {weak_list[1] if len(weak_list)>1 else 'Trees'} — 2 Medium daily\n**Week 3:** {weak_list[2] if len(weak_list)>2 else 'Dynamic Programming'} — 1 Medium + 1 Hard every 2 days\n**Week 4:** Mixed timed practice + mock interviews\n\n## 🔮 Next 5 Recommended Topics\n1. **{weak_list[0] if weak_list else 'Dynamic Programming'}** — highest weakness score\n2. **Two Pointers** — high ROI\n3. **Binary Search** — appears in most Medium+ problems\n4. **BFS/DFS** — graph traversal is interview essential\n5. **Sliding Window** — powerful pattern\n\n## 💡 3 Actionable Tips\n1. After each problem, write the approach before moving on\n2. Revisit fast solves — quick solutions often mean shallow understanding\n3. Practice across platforms for variety\n\n> 💡 Set `ANTHROPIC_API_KEY` env var for full AI-powered analysis!"""
        return jsonify({'result': result})

    try:
        body = json.dumps({
            "model": "claude-sonnet-4-20250514", "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages', data=body,
            headers={'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY,
                     'anthropic-version': '2023-06-01'}, method='POST'
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
        return jsonify({'result': result['content'][0]['text']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    app.run(debug=True, port=5000)
