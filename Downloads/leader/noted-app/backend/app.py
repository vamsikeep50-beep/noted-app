import os
import io
import json
import csv
import uuid
import base64
import qrcode

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from models import db, User, Event, Connection
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# Configure CORS to allow your production frontend
CORS(app, resources={r"/api/*": {"origins": ["https://noted-verse.netlify.app", "http://localhost:5173", "http://localhost:5174"]}}, 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Use persistent storage path if on Render (configured in render.yaml)
database_uri = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'noted-v2-secret-key-change-in-prod')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

db.init_app(app)
jwt = JWTManager(app)

# Initialize Firebase Admin
fb_creds_json = os.environ.get('FIREBASE_SERVICE_ACCOUNT')
if fb_creds_json:
    try:
        fb_creds_dict = json.loads(fb_creds_json)
        cred = credentials.Certificate(fb_creds_dict)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"Error initializing Firebase with service account: {e}")
else:
    print("FIREBASE_SERVICE_ACCOUNT environment variable not set.")


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return jsonify({
        'status': 'online',
        'message': 'Noted API is running',
        'firebase_admin': 'initialized' if firebase_admin._apps else 'not_initialized'
    })


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def current_user_id():
    return int(get_jwt_identity())


def auto_extract_tags(transcript: str) -> list:
    """Simple keyword-based tag extraction — no external API needed."""
    if not transcript:
        return []
    text = transcript.lower()
    tag_map = {
        '#Founder': ['founder', 'co-founder', 'started', 'built a company'],
        '#Investor': ['investor', 'invest', 'vc', 'venture', 'funding', 'seed'],
        '#Hiring': ['hiring', "we're hiring", 'looking for', 'recruiting', 'job opening'],
        '#Student': ['student', 'college', 'university', 'grad', 'intern', 'campus'],
        '#Developer': ['developer', 'engineer', 'coding', 'software', 'programmer', 'backend', 'frontend'],
        '#Designer': ['designer', 'design', 'ux', 'ui', 'figma', 'creative'],
        '#AI': ['ai', 'machine learning', 'gpt', 'llm', 'ml', 'deep learning', 'artificial intelligence'],
        '#Startup': ['startup', 'early stage', 'pre-seed', 'mvp', 'launch'],
        '#Collab': ['collaborate', 'collab', 'partner', 'work together', 'team up'],
        '#Marketing': ['marketing', 'growth', 'seo', 'content', 'ads', 'branding'],
        '#Sales': ['sales', 'leads', 'crm', 'pipeline', 'revenue'],
        '#Finance': ['finance', 'accounting', 'cfo', 'budget', 'financial'],
        '#Health': ['health', 'healthcare', 'medtech', 'biotech', 'wellness'],
    }
    found = []
    for tag, keywords in tag_map.items():
        if any(k in text for k in keywords):
            found.append(tag)
    return found[:6]  # max 6 tags


def extract_intent(transcript: str) -> str:
    if not transcript:
        return 'networking'
    text = transcript.lower()
    if any(w in text for w in ['hiring', 'job', 'position', 'role']):
        return 'hiring'
    if any(w in text for w in ['invest', 'funding', 'seed', 'vc']):
        return 'investment'
    if any(w in text for w in ['collab', 'partner', 'work together']):
        return 'collaboration'
    if any(w in text for w in ['student', 'intern', 'learn']):
        return 'learning'
    return 'networking'


def generate_ai_summary(name: str, role: str, company: str, transcript: str, intent: str) -> str:
    parts = []
    if role:
        parts.append(role)
    if company:
        parts.append(f"at {company}")
    if intent and intent != 'networking':
        parts.append(f"— {intent}")
    if transcript and len(transcript) > 20:
        # Take first sentence of transcript
        first_sentence = transcript.split('.')[0][:80].strip()
        if first_sentence:
            parts.append(f'· "{first_sentence}"')
    if parts:
        return f"{name}: {', '.join(parts[:3])}"
    return f"Met {name} at a networking event."


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'error': 'Missing fields'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    user = User(
        name=data['name'],
        email=data['email'],
        password=generate_password_hash(data['password']),
        bio='',
        plan='free'
    )
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not check_password_hash(user.password, data.get('password', '')):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = create_access_token(identity=str(user.id))
    return jsonify({'token': token, 'user': user.to_dict()})


@app.route('/api/auth/google', methods=['POST'])
def google_login():
    data = request.json
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'error': 'No ID Token provided'}), 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token.get('email')
        name = decoded_token.get('name', 'Google User')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, password='', bio='', plan='free')
            db.session.add(user)
            db.session.commit()
        
        token = create_access_token(identity=str(user.id))
        return jsonify({'token': token, 'user': user.to_dict()})
    except Exception as e:
        return jsonify({'error': str(e)}), 401


@app.route('/api/auth/apple', methods=['POST'])
def apple_login():
    data = request.json
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'error': 'No ID Token provided'}), 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token.get('email')
        # Apple doesn't always provide name in the token
        name = decoded_token.get('name', 'Apple User')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, password='', bio='', plan='free')
            db.session.add(user)
            db.session.commit()
            
        token = create_access_token(identity=str(user.id))
        return jsonify({'token': token, 'user': user.to_dict()})
    except Exception as e:
        return jsonify({'error': str(e)}), 401


# ─────────────────────────────────────────────
# USER PROFILE
# ─────────────────────────────────────────────
@app.route('/api/user', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    uid = current_user_id()
    user = User.query.get(uid)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    if request.method == 'GET':
        return jsonify(user.to_dict())
    data = request.json
    user.name = data.get('name', user.name)
    user.bio = data.get('bio', user.bio)
    user.avatar = data.get('avatar', user.avatar)
    user.linkedin = data.get('linkedin', user.linkedin)
    user.portfolio = data.get('portfolio', user.portfolio)
    db.session.commit()
    return jsonify({'success': True, 'user': user.to_dict()})


# Upgrade plan (no real payment — just toggles plan)
@app.route('/api/user/upgrade', methods=['POST'])
@jwt_required()
def upgrade_plan():
    uid = current_user_id()
    user = User.query.get(uid)
    user.plan = 'pro'
    db.session.commit()
    return jsonify({'success': True, 'plan': 'pro'})


# Get own QR code (user's personal profile QR)
@app.route('/api/user/qr', methods=['GET'])
@jwt_required()
def user_qr():
    uid = current_user_id()
    user = User.query.get(uid)
    qr_data = json.dumps({
        'type': 'noted_user',
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'company': '',
        'linkedin': user.linkedin or ''
    })
    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode('utf-8')
    return jsonify({'qr': f'data:image/png;base64,{b64}'})


# ─────────────────────────────────────────────
# EVENTS
# ─────────────────────────────────────────────
@app.route('/api/events', methods=['GET', 'POST'])
@jwt_required()
def events():
    uid = current_user_id()
    if request.method == 'GET':
        evts = Event.query.filter_by(user_id=uid).order_by(Event.created_at.desc()).all()
        result = []
        for e in evts:
            d = e.to_dict()
            d['connection_count'] = Connection.query.filter_by(event_id=e.id, user_id=uid).count()
            result.append(d)
        return jsonify(result)
    data = request.json
    token = str(uuid.uuid4())[:8].upper()
    evt = Event(
        user_id=uid,
        name=data['name'],
        description=data.get('description', ''),
        location=data.get('location', ''),
        qr_token=token,
        date=datetime.strptime(data['date'], '%Y-%m-%d').date() if data.get('date') else datetime.utcnow().date()
    )
    db.session.add(evt)
    db.session.commit()
    return jsonify(evt.to_dict()), 201


@app.route('/api/events/<int:event_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def event_detail(event_id):
    uid = current_user_id()
    evt = Event.query.filter_by(id=event_id, user_id=uid).first()
    if not evt:
        return jsonify({'error': 'Not found'}), 404
    if request.method == 'GET':
        d = evt.to_dict()
        conns = Connection.query.filter_by(event_id=event_id, user_id=uid).all()
        d['connections'] = [c.to_dict() for c in conns]
        # Stats
        all_tags = []
        for c in conns:
            all_tags.extend(c.tags)
        from collections import Counter
        tag_counts = dict(Counter(all_tags).most_common(5))
        d['stats'] = {
            'total': len(conns),
            'tag_breakdown': tag_counts,
        }
        return jsonify(d)
    if request.method == 'DELETE':
        db.session.delete(evt)
        db.session.commit()
        return jsonify({'success': True})
    data = request.json
    evt.name = data.get('name', evt.name)
    evt.description = data.get('description', evt.description)
    evt.location = data.get('location', evt.location)
    db.session.commit()
    return jsonify(evt.to_dict())


# Event QR code image
@app.route('/api/events/<int:event_id>/qr', methods=['GET'])
@jwt_required()
def event_qr(event_id):
    uid = current_user_id()
    evt = Event.query.filter_by(id=event_id, user_id=uid).first()
    if not evt:
        return jsonify({'error': 'Not found'}), 404
    qr_data = json.dumps({'type': 'noted_event', 'token': evt.qr_token, 'name': evt.name})
    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode('utf-8')
    return jsonify({'qr': f'data:image/png;base64,{b64}', 'token': evt.qr_token})


# Lookup event by QR token (public, no auth needed for scanning)
@app.route('/api/events/join/<token>', methods=['GET'])
def event_by_token(token):
    evt = Event.query.filter_by(qr_token=token).first()
    if not evt:
        return jsonify({'error': 'Event not found'}), 404
    return jsonify({'id': evt.id, 'name': evt.name, 'description': evt.description, 'location': evt.location})


# ─────────────────────────────────────────────
# CONNECTIONS
# ─────────────────────────────────────────────
@app.route('/api/connections', methods=['GET', 'POST'])
@jwt_required()
def handle_connections():
    uid = current_user_id()
    if request.method == 'GET':
        q = request.args.get('q', '').lower()
        tag = request.args.get('tag', '')
        event_id = request.args.get('event_id', '')

        query = Connection.query.filter_by(user_id=uid)
        if event_id:
            query = query.filter_by(event_id=int(event_id))
        conns = query.order_by(Connection.date.desc()).all()

        if q:
            conns = [c for c in conns if q in c.name.lower() or q in (c.event or '').lower() or q in (c.transcript or '').lower() or q in (c.ai_summary or '').lower()]
        if tag:
            conns = [c for c in conns if tag in c.tags]
        return jsonify([c.to_dict() for c in conns])

    data = request.json
    user = User.query.get(uid)

    # Free plan: max 50 connections
    if user.plan == 'free':
        count = Connection.query.filter_by(user_id=uid).count()
        if count >= 50:
            return jsonify({'error': 'Free plan limit reached. Upgrade to Pro for unlimited connections.', 'limit': True}), 403

    # Auto-process transcript
    transcript = data.get('transcript', '')
    tags = data.get('tags') or auto_extract_tags(transcript)
    intent = data.get('intent') or extract_intent(transcript)
    ai_summary = data.get('aiSummary') or generate_ai_summary(
        data['name'], data.get('role', ''), data.get('company', ''), transcript, intent
    )

    conn = Connection(
        user_id=uid,
        event_id=data.get('event_id'),
        name=data['name'],
        company=data.get('company', ''),
        role=data.get('role', ''),
        photo=data.get('photo'),
        email_contact=data.get('email_contact', ''),
        phone=data.get('phone', ''),
        linkedin=data.get('linkedin', ''),
        event=data.get('event', ''),
        voice_note=data.get('voiceNote'),
        highlight_clip=data.get('highlightClip'),
        transcript=transcript,
        ai_summary=ai_summary,
        intent=intent,
        reminder=datetime.strptime(data['reminder'], '%Y-%m-%d').date() if data.get('reminder') else None,
        follow_up_status='none',
        private_note=data.get('privateNote', ''),
        public_note=data.get('publicNote', ''),
        is_private=data.get('isPrivate', True),
    )
    conn.tags = tags
    db.session.add(conn)
    db.session.commit()
    return jsonify(conn.to_dict()), 201


@app.route('/api/connections/<int:conn_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def connection_detail(conn_id):
    uid = current_user_id()
    conn = Connection.query.filter_by(id=conn_id, user_id=uid).first()
    if not conn:
        return jsonify({'error': 'Not found'}), 404
    if request.method == 'GET':
        return jsonify(conn.to_dict())
    if request.method == 'DELETE':
        db.session.delete(conn)
        db.session.commit()
        return jsonify({'success': True})
    # PUT — update any field
    data = request.json
    for field in ['name', 'company', 'role', 'photo', 'email_contact', 'phone', 'linkedin',
                  'event', 'transcript', 'ai_summary', 'intent', 'follow_up_status',
                  'reminder_note', 'is_private', 'public_note', 'private_note']:
        if field in data:
            setattr(conn, field, data[field])
    if 'tags' in data:
        conn.tags = data['tags']
    if 'reminder' in data:
        conn.reminder = datetime.strptime(data['reminder'], '%Y-%m-%d').date() if data['reminder'] else None
    if 'voiceNote' in data:
        conn.voice_note = data['voiceNote']
    if 'highlightClip' in data:
        conn.highlight_clip = data['highlightClip']
    db.session.commit()
    return jsonify(conn.to_dict())


# AI process: extract tags + summary + intent from transcript
@app.route('/api/connections/<int:conn_id>/process', methods=['POST'])
@jwt_required()
def process_connection(conn_id):
    uid = current_user_id()
    conn = Connection.query.filter_by(id=conn_id, user_id=uid).first()
    if not conn:
        return jsonify({'error': 'Not found'}), 404
    data = request.json
    transcript = data.get('transcript', conn.transcript or '')
    conn.transcript = transcript
    conn.tags = auto_extract_tags(transcript)
    conn.intent = extract_intent(transcript)
    conn.ai_summary = generate_ai_summary(conn.name, conn.role, conn.company, transcript, conn.intent)
    db.session.commit()
    return jsonify({'tags': conn.tags, 'intent': conn.intent, 'aiSummary': conn.ai_summary, 'transcript': transcript})


# Export connections as CSV
@app.route('/api/connections/export', methods=['GET'])
@jwt_required()
def export_connections():
    uid = current_user_id()
    conns = Connection.query.filter_by(user_id=uid).order_by(Connection.date.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Company', 'Role', 'Email', 'Phone', 'LinkedIn', 'Event', 'Date', 'Tags', 'AI Summary', 'Intent', 'Reminder', 'Follow-up Status', 'Transcript'])
    for c in conns:
        writer.writerow([
            c.name, c.company or '', c.role or '', c.email_contact or '',
            c.phone or '', c.linkedin or '', c.event or '',
            c.date.strftime('%Y-%m-%d') if c.date else '',
            ', '.join(c.tags),
            c.ai_summary or '', c.intent or '',
            c.reminder.strftime('%Y-%m-%d') if c.reminder else '',
            c.follow_up_status or '',
            (c.transcript or '').replace('\n', ' ')[:200]
        ])
    output.seek(0)
    buf = io.BytesIO()
    buf.write(output.getvalue().encode('utf-8'))
    buf.seek(0)
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='noted_connections.csv')


# ─────────────────────────────────────────────
# AI ASSISTANT — network search
# ─────────────────────────────────────────────
@app.route('/api/ai/ask', methods=['POST'])
@jwt_required()
def ai_ask():
    uid = current_user_id()
    query = (request.json.get('query') or '').lower().strip()
    if not query:
        return jsonify({'error': 'Query required'}), 400

    conns = Connection.query.filter_by(user_id=uid).all()
    results = []
    for c in conns:
        score = 0
        searchable = ' '.join([
            c.name or '', c.company or '', c.role or '', c.event or '',
            c.transcript or '', c.ai_summary or '', c.intent or '',
            ' '.join(c.tags)
        ]).lower()
        for word in query.split():
            if word in searchable:
                score += 1
        if score > 0:
            d = c.to_dict()
            d['_score'] = score
            results.append(d)

    results.sort(key=lambda x: x['_score'], reverse=True)
    top = results[:6]

    # Generate response text
    if not top:
        answer = f"I couldn't find anyone matching \"{query}\" in your network."
    else:
        names = ', '.join([r['name'] for r in top[:3]])
        answer = f"Found {len(top)} connection(s) related to \"{query}\": {names}{'...' if len(top) > 3 else '.'}"

    return jsonify({'answer': answer, 'results': top})


# Smart suggestions: who to reconnect with
@app.route('/api/ai/suggestions', methods=['GET'])
@jwt_required()
def ai_suggestions():
    uid = current_user_id()
    today = datetime.utcnow().date()
    thirty_days_ago = today - timedelta(days=30)

    # People met recently with no follow-up
    conns = Connection.query.filter_by(user_id=uid, follow_up_status='none').filter(
        Connection.date >= thirty_days_ago
    ).order_by(Connection.date.desc()).limit(5).all()

    suggestions = []
    for c in conns:
        days_since = (today - c.date).days if c.date else 0
        msg = f"You met {c.name} {days_since} days ago"
        if c.intent and c.intent != 'networking':
            msg += f" ({c.intent})"
        msg += " — consider following up!"
        suggestions.append({'connection': c.to_dict(), 'message': msg})

    return jsonify(suggestions)


# ─────────────────────────────────────────────
# INSIGHTS DASHBOARD
# ─────────────────────────────────────────────
@app.route('/api/insights', methods=['GET'])
@jwt_required()
def insights():
    uid = current_user_id()
    from collections import Counter
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    all_conns = Connection.query.filter_by(user_id=uid).all()
    total = len(all_conns)

    # This week
    week_conns = [c for c in all_conns if c.date and c.date >= week_ago]
    month_conns = [c for c in all_conns if c.date and c.date >= month_ago]

    # Follow-up rate
    with_reminder = [c for c in all_conns if c.reminder]
    followed_up = [c for c in all_conns if c.follow_up_status == 'done']
    follow_rate = round((len(followed_up) / total * 100) if total else 0)

    # Tags
    all_tags = []
    for c in all_conns:
        all_tags.extend(c.tags)
    tag_counts = dict(Counter(all_tags).most_common(8))

    # Events attended
    event_ids = set(c.event_id for c in all_conns if c.event_id)
    events_count = len(event_ids)

    # Intent breakdown
    intents = [c.intent for c in all_conns if c.intent]
    intent_counts = dict(Counter(intents).most_common(5))

    # Timeline — connections per day last 30 days
    day_counts = Counter()
    for c in month_conns:
        if c.date:
            day_counts[c.date.strftime('%Y-%m-%d')] += 1
    timeline = [{'date': d, 'count': cnt} for d, cnt in sorted(day_counts.items())]

    # Overdue follow-ups
    overdue = [c for c in all_conns if c.reminder and c.reminder < today and c.follow_up_status != 'done']
    for c in overdue:
        c.follow_up_status = 'overdue'
    if overdue:
        db.session.commit()

    return jsonify({
        'total': total,
        'this_week': len(week_conns),
        'this_month': len(month_conns),
        'pending_reminders': len(with_reminder),
        'follow_up_rate': follow_rate,
        'events_attended': events_count,
        'top_tags': tag_counts,
        'intent_breakdown': intent_counts,
        'timeline': timeline,
        'overdue_count': len(overdue),
    })


# ─────────────────────────────────────────────
# FOLLOW-UP Quick update
# ─────────────────────────────────────────────
@app.route('/api/connections/<int:conn_id>/followup', methods=['POST'])
@jwt_required()
def followup(conn_id):
    uid = current_user_id()
    conn = Connection.query.filter_by(id=conn_id, user_id=uid).first()
    if not conn:
        return jsonify({'error': 'Not found'}), 404
    data = request.json
    conn.follow_up_status = data.get('status', 'done')
    db.session.commit()
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
