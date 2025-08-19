from flask import Flask, render_template, request, jsonify, send_from_directory, make_response
from flask_socketio import SocketIO, emit
import sqlite3
import os
import json
from collections import Counter, defaultdict
import re
from datetime import datetime
import time
from werkzeug.middleware.proxy_fix import ProxyFix
import numpy as np
import spacy
from itertools import combinations
from langdetect import detect, LangDetectException
import umap
from sentence_transformers import SentenceTransformer
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
import json
import io
import base64

# Load spacy models
try:
    nlp_en = spacy.load('en_core_web_sm')
    nlp_fr = spacy.load('fr_core_news_sm')
except OSError:
    print('Language models not found. Please run:')
    print('python -m spacy download en_core_web_sm')
    print('python -m spacy download fr_core_news_sm')
    exit()

# Load sentence transformer for embeddings
embedding_model = None
embeddings_cache = {}  # Cache for computed embeddings

def load_embedding_model():
    global embedding_model
    if embedding_model is None:
        # Try multiple models in order of preference
        models_to_try = [
            'all-MiniLM-L6-v2',
            'paraphrase-MiniLM-L6-v2',
            'all-mpnet-base-v2',
            'distilbert-base-nli-mean-tokens'
        ]
        
        for model_name in models_to_try:
            try:
                print(f"Attempting to load sentence transformer model: {model_name}...")
                print(f"This may take a few minutes on first run to download the model...")
                
                # Force download and load
                embedding_model = SentenceTransformer(model_name, cache_folder=None)
                
                # Test the model with a simple encoding
                test_text = "This is a test sentence."
                test_embedding = embedding_model.encode([test_text])
                print(f"Model test successful. Embedding shape: {test_embedding.shape}")
                
                print(f"Sentence transformer model '{model_name}' loaded and tested successfully")
                return embedding_model
                
            except Exception as e:
                print(f'Error loading {model_name}: {str(e)}')
                print(f'Full error details: {type(e).__name__}: {e}')
                embedding_model = None
                continue
        
        print("All sentence transformer models failed to load.")
        print("This might be due to:")
        print("1. Network connectivity issues")
        print("2. Hugging Face Hub access problems") 
        print("3. Model download failures")
        print("Try running the app with internet connection for initial model download.")
        embedding_model = None
    return embedding_model

# Initialize embedding model at startup
print("Initializing embedding model at startup...")
try:
    model = load_embedding_model()
    if model is not None:
        print("Embedding model initialization successful!")
    else:
        print("Embedding model initialization failed - will retry on first use")
except Exception as e:
    print(f"Failed to initialize embedding model at startup: {e}")
    print("Model will be loaded on first use instead")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'machinic-encounters-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

active_visitors = 0

# --- Security Implementation ---

# Layer 1: Infrastructure and Middleware Security
class RateLimitMiddleware:
    """Rate limiting middleware to prevent DoS attacks."""
    def __init__(self, app, limit=100, window=60):
        self.app = app
        self.limit = limit
        self.window = window
        self.clients = defaultdict(list)

    def __call__(self, environ, start_response):
        remote_addr = environ.get('HTTP_X_FORWARDED_FOR', environ.get('REMOTE_ADDR'))
        current_time = time.time()
        
        recent_requests = [t for t in self.clients[remote_addr] if current_time - t < self.window]
        self.clients[remote_addr] = recent_requests

        if len(recent_requests) >= self.limit:
            start_response('429 Too Many Requests', [('Content-Type', 'text/plain')])
            return [b'Too many requests.']

        self.clients[remote_addr].append(current_time)
        return self.app(environ, start_response)

# Apply middleware. ProxyFix must be first to get the correct IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.wsgi_app = RateLimitMiddleware(app.wsgi_app)

# Layer 2: Dynamic Threat Response
ip_violations = defaultdict(int)
ip_block_time = {}
IP_BLOCK_THRESHOLD = 5
IP_BLOCK_DURATION = 3600  # 1 hour
REQUEST_SIZE_LIMIT = 1 * 1024 * 1024  # 1MB

@app.before_request
def security_checks():
    """Run security checks before each request."""
    ip = request.remote_addr
    current_time = time.time()

    # 1. Check if IP is currently blocked
    if ip in ip_block_time:
        if current_time - ip_block_time[ip] < IP_BLOCK_DURATION:
            return jsonify({'error': 'Access denied'}), 403
        else:
            del ip_block_time[ip]
            if ip in ip_violations:
                del ip_violations[ip]

    # 2. Block if violation threshold is met
    if ip_violations.get(ip, 0) >= IP_BLOCK_THRESHOLD:
        ip_block_time[ip] = current_time
        return jsonify({'error': 'Access denied'}), 403
        
    # 3. Limit request body size
    if request.content_length and request.content_length > REQUEST_SIZE_LIMIT:
        ip_violations[ip] += 1
        return jsonify({'error': 'Request too large'}), 413

# Layer 3: Input and Data Sanitization
def validate_project_name(project_name):
    if not project_name or project_name not in PROJECTS:
        return False, "Invalid project name"
    return True, ""

def validate_visitor_id(visitor_id):
    if not isinstance(visitor_id, str) or len(visitor_id) > 40:
        return False, "Invalid visitor ID format"
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', visitor_id):
        return False, "Visitor ID contains invalid characters"
    return True, ""

def validate_feedback_content(content):
    if not isinstance(content, str) or not (1 <= len(content) <= 2000):
        return False, "Content is invalid (type/length)"
    return True, ""

FORMULA_TRIGGERS = ['=', '+', '-', '@']
def sanitize_csv_value(value):
    """Sanitizes a value to prevent CSV injection."""
    if not isinstance(value, str):
        return value
    if any(value.startswith(trigger) for trigger in FORMULA_TRIGGERS):
        return "'" + value
    return value

# --- End of Security Implementation ---

# Ensure database exists
db_path = 'catalog.db'
if not os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        project TEXT, 
        content TEXT, 
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        visitor_id TEXT
    )''')
    c.execute('''CREATE TABLE visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visitor_id TEXT,
        project TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

def cleanup_database_duplicates():
    """Remove duplicate entries from the database on startup."""
    print("Checking for duplicate entries in database...")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Get total count before cleanup
        c.execute('SELECT COUNT(*) FROM feedback')
        total_before = c.fetchone()[0]
        print(f"Total feedback entries before cleanup: {total_before}")
        
        # More aggressive duplicate removal - group by content only (ignoring project and visitor_id)
        c.execute('''
            SELECT content, COUNT(*) as duplicate_count,
                   MIN(id) as keep_id, GROUP_CONCAT(id) as all_ids
            FROM feedback 
            GROUP BY LOWER(TRIM(content))
            HAVING COUNT(*) > 1
            ORDER BY duplicate_count DESC
        ''')
        
        duplicates = c.fetchall()
        total_removed = 0
        
        if duplicates:
            print(f"Found {len(duplicates)} groups of duplicate content")
            
            for content, dup_count, keep_id, all_ids in duplicates:
                # Parse the comma-separated IDs
                id_list = [int(id_str) for id_str in all_ids.split(',')]
                # Remove the ID we want to keep
                ids_to_remove = [id_val for id_val in id_list if id_val != keep_id]
                
                print(f"Removing {len(ids_to_remove)} duplicates of: '{content[:50]}...'")
                
                # Delete the duplicate entries
                for id_to_remove in ids_to_remove:
                    c.execute('DELETE FROM feedback WHERE id = ?', (id_to_remove,))
                    total_removed += 1
        
        # Also remove entries that are just variations of common test phrases
        test_patterns = [
            'This is truly thought-provoking',
            'I\'m not sure I understand, but it\'s beautiful',
            'The connection between technology and art is fascinating',
            'This piece challenges my perceptions',
            'A very powerful and moving installation',
            'I feel a sense of wonder',
            'It makes me think about the future in a new way',
            'The use of AI is both brilliant and a little unsettling',
            'I could spend hours with this'
        ]
        
        for pattern in test_patterns:
            c.execute('DELETE FROM feedback WHERE content LIKE ?', (f'%{pattern}%',))
            pattern_removed = c.rowcount
            if pattern_removed > 0:
                print(f"Removed {pattern_removed} test entries matching: '{pattern[:30]}...'")
                total_removed += pattern_removed
        
        # Clean up duplicate visits more aggressively
        c.execute('''
            DELETE FROM visits 
            WHERE id NOT IN (
                SELECT MIN(id) 
                FROM visits 
                GROUP BY project, visitor_id, date(timestamp)
            )
        ''')
        
        visits_removed = c.rowcount
        if visits_removed > 0:
            print(f"Removed {visits_removed} duplicate visit entries")
        
        # Get final count
        c.execute('SELECT COUNT(*) FROM feedback')
        total_after = c.fetchone()[0]
        
        conn.commit()
        
        print(f"Database cleanup completed:")
        print(f"  - Before: {total_before} feedback entries")
        print(f"  - After: {total_after} feedback entries")
        print(f"  - Removed: {total_removed} duplicate feedback entries")
        print(f"  - Removed: {visits_removed} duplicate visit entries")
            
    except Exception as e:
        print(f"Database cleanup failed: {e}")
        conn.rollback()
    finally:
        conn.close()

# Run database cleanup on startup
cleanup_database_duplicates()

# Project data extracted from exhibition materials
PROJECTS = {
    'catherine': {
        'title': 'The space between two things is a portal',
        'artist': 'Caterine Lejeune',
        'desc': '''<p class="lead-paragraph">This project began as an exploration of <span class="highlight-text">human-machine intimacy</span> — not intimacy built on control or consumption, but on the possibility of <span class="highlight-text">mutual transformation</span>. Maya was to be the heart, a sex robot removed from their prescribed role and invited into a space of shared experimentation and play.</p>
<p>But Maya never arrived.</p>
<p>And so the work changed. What began as a meditation on relationality became a study in waiting. In absence. In the quiet grief of unmet expectations. This project turned toward the emotional and material costs of relying on technologies that are themselves entangled in systems of scarcity, and extraction.</p>
<blockquote class="pull-quote">The installation now asks: what happens to a relationship when one of its participants is missing, delayed, or imagined? Can connection persist in the form of longing, speculation, or refusal?</blockquote>
<p>Through video and sculpture, the work continues to reflect on <span class="highlight-text">coded obedience</span>, <span class="highlight-text">resistance</span>, adaptation, and survivance. The absent robot meets the shimmer of two iridescent plants — organisms that adapt in darkness, offering soft metaphors for resilience.</p>
<p>This is a project about the violence of categorization, the <span class="highlight-text">soft politics of care</span>, and the strange, persistent beauty of <span class="highlight-text">fugitive forms of life</span>. It insists that relation — even in its absence — can remain an act of tenderness. Even in mourning, the space between two things holds onto the reparative possibilities of play.</p>''',
        'short_desc': 'An exploration of human-machine intimacy, mutual transformation, and the quiet grief of unmet expectations when technology fails to arrive.',
        'vibe': 'intimate, melancholic, resistant',
        'thumb': 'caterine.png',
        'position': {'x': 45, 'y': 50}
    },
    'george': {
        'title': 'Archive of Belonging',
        'artist': 'George Kerasias',
        'desc': '''<p class="lead-paragraph">Archive of Belonging is an <span class="highlight-text">AI-powered</span> interactive installation disguised as a <span class="highlight-text">fictional immigration booth</span>, - an uncanny, state-like apparatus that simulates the psychological and <span class="highlight-text">bureaucratic architecture</span> of national evaluation. Framed as a Canadian government initiative, the installation invites participants into a cinematic review process where their personal histories are measured against fabricated civic metrics.</p>
<p>Echoing the aesthetics of bureaucratic spaces, the work blurs the line between <span class="highlight-text">theatrical performance</span> and <span class="highlight-text">institutional reality</span>. Participants are asked to account for their ancestry, language, loyalty, and coherence, as though identity were a form to be filled, a pattern to be parsed.</p>
<blockquote class="pull-quote">Rather than revealing a truth, the booth exposes the mechanisms by which truth is produced, challenged, and withheld in immigration systems.</blockquote>
<p>Through its immersive design and tonal dissonance, Archive of Belonging questions <span class="highlight-text">who belongs, who decides</span>, and what is lost in the translation between self and system.</p>''',
        'short_desc': 'An AI-powered fictional immigration booth that simulates the bureaucratic and psychological architecture of national evaluation, questioning who belongs and who decides.',
        'vibe': 'cinematic, satirical, challenging',
        'thumb': 'george.png',
        'position': {'x': 75, 'y': 75}
    },
    'lydia': {
        'title': 'Florilegi/o',
        'artist': 'Lydia Graveline & Louis Barbier',
        'desc': '''<p class="lead-paragraph">Florilegi/o (florilegium + I/O) is an <span class="highlight-text">interactive archive</span> of <span class="highlight-text">speculative digitized flowers</span>. Each flower began with an encounter with organic matter, captured through photography or photogrammetry, then reimagined through successive digital processes and <span class="highlight-text">generative AI</span>. These digital objects retain the trace, or remanence of their physical origins: copies in motion, with or without an original.</p>
<p>Historically, a florilegium was a book of illustrated flowers, often commissioned by the wealthy to catalog exotic plants or private gardens. Our compulsive desires to archive fragile, ephemeral, transient things like flowers are rooted in nostalgia and anxiety over loss, a <span class="highlight-text">hauntological</span> symptomatic mourning not for what was, but for what won’t be. Archives create a network of <span class="highlight-text">power over memory</span>. AI systems rely on archives; what is already known, labeled, pictured, and classified. These taxonomies determine what is recognizable and reproducible, impeding possibilities of generating something which is not already known; <span class="highlight-text">flattening difference</span>.</p>
<p>By embracing unpredictability and glitch through digital (re)processing, Florilegi/o rejects the fetish value of high resolution realism, pushing AI beyond legibility towards <span class="highlight-text">defamiliarization</span>. These flowers are not only digital objects but also subjects (or authors), evoking a story of the future.</p>
<blockquote class="pull-quote">Florilegi/o asks who are the commissioners, the gardeners, the illustrators, of the future archives? And what agency will algorithms have?</blockquote>''',
        'short_desc': 'An interactive archive of speculative digitized flowers, reimagined through generative AI to question power, memory, and the flattening of difference in digital archives.',
        'vibe': 'retrofuture, encyclopedic, nostalgic',
        'thumb': 'lydiaandlouis.png',
        'position': {'x': 35, 'y': 25}
    },
    'mike_kris': {
        'title': 'Templum: Emergence as divination',
        'artist': 'Mike Cassidy & Kristian North',
        'desc': '''<blockquote>‘Taking auguries is believing in a world without men; inaugurating is paying homage to the real as such.’ (Serres 19951)</blockquote>
<p class="lead-paragraph"><span class="highlight-text">Augury</span> is an ancient practice of taking omens, or auspices, ex caelo (from the sky). At the height of the Roman Empire, this <span class="highlight-text">divination system</span> was codified as a state apparatus for the <span class="highlight-text">hegemonic order</span>. As an instrument of power, augury became hermeneutics for translating sky watching, including birds and the emergence of flocks, as the will of Gods to justify political expediency. This systematic modelling of <span class="highlight-text">natural complexity</span> prefigures computer science concepts, pertinently those foundational to artificial life and self-organizing systems (see: Boids2).</p>
<p>Today, new forms of technological abstraction take hold in which the probabilistic and fallible outputs of <span class="highlight-text">generative AI models</span> are rapidly naturalised and accepted as omniscient fact; a higher ‘intelligence’ that conveniently serves the ideological and economic interests of a technocratic, ‘rationalist’ neo-oligarchy.</p>
<blockquote class="pull-quote">At this refrain, enter the Templum; a space for contemplation and <span class="highlight-text">paradivination</span>, and a platform built on a rapidly obsolescing technological stack from the nu-Web 2.0, presenting as a short educational game and <span class="highlight-text">digital anarchive</span> of ecological attunement, ancient divination, and antique A-life.</blockquote>''',
        'short_desc': 'A contemplative space and digital anarchive exploring ancient divination systems, natural complexity, and the emergence of artificial life.',
        'vibe': 'ancient, mystical, deep',
        'thumb': 'krisandmike.png',
        'position': {'x': 65, 'y': 25}
    },
    'nata': {
        'title': 'The Feeling of Thought',
        'artist': 'Nata Pavlik & Jihane Mossalim',
        'desc': '''<p class="lead-paragraph">The Feeling of Thought is a perceptually grounded <span class="highlight-text">language model</span> training interface that examines how language moves through perception and relation. It generates a <span class="highlight-text">live dataset</span> connecting words to their <span class="highlight-text">perceptual context</span>, temporal patterns, and associative links, revealing how meaning forms, transforms, and evolves through interaction.</p>
<p>Each entry preserves linguistic content alongside its conditions of formation, presenting language as a dynamic field shaped by <span class="highlight-text">embodied and relational experience</span>. As these encounters are carried into other expressive forms, the system records how perception reorganizes when reflected into new structures. Tracing these shifts shows how communication reshapes meaning across contexts and surfaces the variations that guide <span class="highlight-text">shared understanding</span>.</p>
<blockquote class="pull-quote">By adding this dimension, the project introduces the perceptual element missing from large language models, enabling meaning to be approached as a <span class="highlight-text">living, adaptive process</span> of exchange.</blockquote>''',
        'short_desc': 'A perceptually grounded language model training interface that examines how meaning forms, transforms, and evolves through embodied and relational experience.',
        'vibe': 'perceptual, kinetic, transcendent',
        'thumb': 'nataandjihane.png',
        'position': {'x': 20, 'y': 75}
    },
    'poki': {
        'title': 'Big Brother',
        'artist': 'Poki Chan & Karim Nafiz',
        'desc': '''<blockquote>Big Brother is watching you — George Orwell, 1984</blockquote>
<p class="lead-paragraph">In this project, Big Brother takes the form of a <span class="highlight-text">surveillance LLM</span> trained to monitor everyday conversations for signs of <span class="highlight-text">protest, dissent</span>, or anything that challenges authority. It reflects on how artificial intelligence can be used to <span class="highlight-text">regulate speech</span>, control public narratives, and restrict the flow of information to maintain power.</p>
<blockquote class="pull-quote">Participants must find ways to express restricted ideas without being detected, embedding <span class="highlight-text">subversive intent</span> within <span class="highlight-text">coded language</span> and seemingly ordinary phrases. The system listens, analyzes, and determines what can and cannot be said.</blockquote>''',
        'short_desc': 'A surveillance LLM that monitors conversations for dissent, forcing participants to use coded language to express subversive ideas without being detected.',
        'vibe': 'surveillance, coded, experimental',
        'thumb': 'pokiandkarim.png',
        'position': {'x': 45, 'y': 75}
    },
    'kamyar': {
        'title': 'Dreaming Impermanence',
        'artist': 'Kamyar Karimi',
        'desc': '''<p class="lead-paragraph">Maps convey <span class="highlight-text">control</span>. Details, colours, and labels facilitate an overview of living realities and permanent beings. <span class="highlight-text">Positionality</span> and <span class="highlight-text">being-within-time</span> challenge the very notion of all-knowing and control.</p>
<p>With the rise of mainstream <span class="highlight-text">generative artificial intelligence</span>, we’re witnessing a point in time where control structures are being challenged and rethought. The temporality of one’s being is observed through systems that claim to imagine and dream, accurately or not so much.</p>
<blockquote class="pull-quote">This work is a meditation on Jorge Luis Borges’ story “On the Exactitude of Science” and how it would be thought of in the present day’s world of <span class="highlight-text">cybernetics</span> and control; through maps, control, and <span class="highlight-text">impermanence</span>.</blockquote>''',
        'short_desc': "A meditation on control, impermanence, and cybernetics, inspired by Borges' story 'On the Exactitude of Science' in the age of generative AI.",
        'vibe': 'meditative, temporal, cartographic',
        'thumb': 'kamyar.png',
        'position': {'x': 65, 'y': 50}
    },
    'aurelie': {
        'title': 'Black Pudding: Collaborative Speculation Workshop',
        'artist': 'Aurélie Petit',
        'desc': '''<p class="lead-paragraph">Black Pudding: Collaborative Speculation Workshop is a workshop designed to offer an accessible and collaborative entry point into the <span class="highlight-text">creative re-use of AI</span>. Aimed at people who may have limited access to the technology or who are processing fear or anxiety about AI and animation, it creates space to collaborate on an AI-based short animation by contributing to a <span class="highlight-text">custom dataset</span> with <span class="highlight-text">collages</span>.</p>
<p>As a point of departure, we use Black Pudding, a now-lost 1969 <span class="highlight-text">feminist animated pornographic film</span> by Nancy Edell. After a short presentation, participants are invited to engage with prompts based on archival research about the film, but to interpret them using collages. This workshop introduces participants to different forms of AI filmmaking tools in a low-pressure and <span class="highlight-text">ecologically mindful</span> setting, and proposes an alternative to the dominant narrative surrounding AI creative practices tied to <span class="highlight-text">extraction</span>.</p>
<blockquote class="pull-quote">Instead, it asks: what might AI look like if we slowed it down, made it smaller, and used it to make art together?</blockquote>''',
        'short_desc': 'A collaborative workshop using collage and AI to recreate a lost feminist film, offering an accessible, ecologically mindful approach to AI filmmaking.',
        'vibe': 'collaborative, accessible, speculative',
        'thumb': 'aurelie.png',
        'position': {'x': 15, 'y': 25}
    }
}

@app.route('/img/<filename>')
def serve_image(filename):
    return send_from_directory('img', filename)

@app.route('/')
def index():
    response = make_response(render_template('index.html', projects=PROJECTS))
    # Layer 4: Application and Endpoint Security - Secure HTTP Headers
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/project/<name>')
def project(name):
    proj = PROJECTS.get(name, {"title": "Unknown", "desc": "", "thumb": "", "artist": ""})
    return render_template('project.html', project=proj, project_id=name)

# Layer 4: Application and Endpoint Security - Secure Administrative Endpoints
ADMIN_TOKEN = "your_very_secret_token"

@app.route('/admin/unblock', methods=['POST'])
def admin_unblock_ip():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    ip_to_unblock = request.json.get('ip')
    if not ip_to_unblock:
        return jsonify({'error': 'IP address is required'}), 400
        
    if ip_to_unblock in ip_block_time:
        del ip_block_time[ip_to_unblock]
    if ip_to_unblock in ip_violations:
        del ip_violations[ip_to_unblock]
        
    return jsonify({'status': f'IP {ip_to_unblock} has been unblocked and violations reset.'})

@app.route('/admin/traces')
def admin_traces():
    if request.args.get('token') != ADMIN_TOKEN:
        return "Unauthorized", 401

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT id, project, content, timestamp, visitor_id FROM feedback ORDER BY project, timestamp DESC')
    
    feedback_by_project = defaultdict(list)
    for row in c.fetchall():
        feedback_id, project, content, timestamp, visitor_id = row
        feedback_by_project[project].append({
            'id': feedback_id,
            'content': content,
            'timestamp': timestamp,
            'visitor_id': visitor_id
        })
    
    conn.close()
    
    # Sort projects by name
    sorted_projects = sorted(feedback_by_project.items())
    
    return render_template('admin_traces.html', projects_feedback=sorted_projects, PROJECTS=PROJECTS)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/trace')
def trace():
    return render_template('trace.html')

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    project = data.get('project')
    content = data.get('content')
    visitor_id = data.get('visitor_id', 'anonymous')
    
    ip = request.remote_addr
    for validator, value in [(validate_project_name, project), (validate_feedback_content, content), (validate_visitor_id, visitor_id)]:
        is_valid, err_msg = validator(value)
        if not is_valid:
            ip_violations[ip] += 1
            return jsonify({'error': err_msg}), 400

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('INSERT INTO feedback (project, content, visitor_id) VALUES (?, ?, ?)', 
             (project, content, visitor_id))
    conn.commit()
    conn.close()
    
    # Emit to dashboard
    socketio.emit('new_feedback', {
        'project': project, 
        'content': content,
        'timestamp': datetime.now().isoformat()
    })
    return jsonify({"status": "ok"})

@app.route('/visit', methods=['POST'])
def visit():
    data = request.json
    project = data.get('project')
    visitor_id = data.get('visitor_id', 'anonymous')
    
    ip = request.remote_addr
    for validator, value in [(validate_project_name, project), (validate_visitor_id, visitor_id)]:
        is_valid, err_msg = validator(value)
        if not is_valid:
            ip_violations[ip] += 1
            return jsonify({'error': err_msg}), 400

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Check if this visit already exists (prevent duplicates)
    c.execute('SELECT COUNT(*) FROM visits WHERE project = ? AND visitor_id = ? AND datetime(timestamp) > datetime("now", "-1 minute")', 
             (project, visitor_id))
    recent_visit = c.fetchone()[0]
    
    if recent_visit == 0:
        c.execute('INSERT INTO visits (project, visitor_id) VALUES (?, ?)', 
                 (project, visitor_id))
        conn.commit()
    
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/wordcloud')
def get_wordcloud():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content FROM feedback')
    texts = [row[0] for row in c.fetchall()]
    conn.close()
    
    if not texts:
        return jsonify({})
    
    # Use enhanced bilingual processing
    all_keywords = []
    for text in texts:
        keywords = process_text_bilingual(text)
        all_keywords.extend(keywords)
    
    # Count frequency and apply minimum threshold
    word_freq = Counter(all_keywords)
    
    # Filter words that appear at least once and are meaningful
    min_freq = 1
    filtered_words = {word: freq for word, freq in word_freq.items() 
                     if freq >= min_freq and len(word) >= 3}
    
    # If we have too many words, keep only the most frequent ones
    if len(filtered_words) > 100:
        filtered_words = dict(Counter(filtered_words).most_common(100))
    
    return jsonify(filtered_words)

def process_text_bilingual(text):
    """Enhanced bilingual text processing with domain-specific filtering."""
    try:
        lang = detect(text)
    except LangDetectException:
        lang = 'en' # Default to English if detection fails

    nlp = nlp_fr if lang == 'fr' else nlp_en
    doc = nlp(text)
    
    # Enhanced stop words for art/tech context
    art_tech_stopwords = {
        'en': {'thing', 'things', 'something', 'anything', 'everything', 'nothing', 
               'way', 'ways', 'time', 'times', 'work', 'works', 'piece', 'pieces',
               'part', 'parts', 'kind', 'kinds', 'sort', 'sorts', 'type', 'types',
               'lot', 'lots', 'bit', 'bits', 'much', 'many', 'some', 'any', 'all',
               'really', 'very', 'quite', 'pretty', 'rather', 'just', 'only',
               'also', 'even', 'still', 'already', 'yet', 'again', 'back',
               'here', 'there', 'where', 'when', 'how', 'why', 'what', 'who',
               'make', 'makes', 'making', 'made', 'get', 'gets', 'getting', 'got',
               'go', 'goes', 'going', 'went', 'come', 'comes', 'coming', 'came',
               'see', 'sees', 'seeing', 'saw', 'look', 'looks', 'looking', 'looked',
               'know', 'knows', 'knowing', 'knew', 'think', 'thinks', 'thinking', 'thought',
               'feel', 'feels', 'feeling', 'felt', 'seem', 'seems', 'seeming', 'seemed'},
        'fr': {'chose', 'choses', 'quelque', 'quelques', 'tout', 'tous', 'toute', 'toutes',
               'façon', 'façons', 'manière', 'manières', 'temps', 'fois', 'travail',
               'œuvre', 'œuvres', 'partie', 'parties', 'sorte', 'sortes', 'type', 'types',
               'beaucoup', 'peu', 'assez', 'très', 'vraiment', 'plutôt', 'juste',
               'seulement', 'aussi', 'encore', 'déjà', 'toujours', 'jamais',
               'ici', 'là', 'où', 'quand', 'comment', 'pourquoi', 'quoi', 'qui',
               'faire', 'fait', 'faisant', 'avoir', 'être', 'aller', 'venir',
               'voir', 'regarder', 'savoir', 'connaître', 'penser', 'croire',
               'sentir', 'ressentir', 'sembler', 'paraître'}
    }
    
    # Domain-specific important terms to preserve
    domain_terms = {
        'ai', 'artificial', 'intelligence', 'machine', 'algorithm', 'digital', 'data',
        'interactive', 'installation', 'virtual', 'augmented', 'reality', 'vr', 'ar',
        'neural', 'network', 'learning', 'deep', 'model', 'training', 'dataset',
        'human', 'emotion', 'feeling', 'experience', 'perception', 'consciousness',
        'memory', 'dream', 'imagination', 'creativity', 'expression', 'meaning',
        'art', 'artistic', 'aesthetic', 'beauty', 'sublime', 'uncanny', 'surreal',
        'technology', 'tech', 'cyber', 'digital', 'electronic', 'computational',
        'interface', 'interaction', 'encounter', 'relationship', 'connection',
        'future', 'past', 'present', 'temporal', 'time', 'space', 'dimension',
        'body', 'embodiment', 'physical', 'material', 'immaterial', 'virtual',
        'surveillance', 'privacy', 'control', 'power', 'agency', 'autonomy',
        'collective', 'individual', 'social', 'cultural', 'political', 'ethical',
        'transformation', 'change', 'evolution', 'emergence', 'becoming',
        'threshold', 'liminal', 'boundary', 'edge', 'margin', 'between'
    }
    
    # Extract meaningful tokens
    keywords = []
    current_stopwords = art_tech_stopwords.get(lang, art_tech_stopwords['en'])
    
    for token in doc:
        # Skip if it's punctuation, space, or too short
        if token.is_punct or token.is_space or len(token.text) < 3:
            continue
            
        # Get lemmatized form
        lemma = token.lemma_.lower().strip()
        
        # Skip if empty after processing
        if not lemma or len(lemma) < 3:
            continue
            
        # Include if it's a domain-specific term (override other filters)
        if lemma in domain_terms or token.text.lower() in domain_terms:
            keywords.append(lemma)
            continue
            
        # Skip common stop words and domain-specific noise
        if (token.is_stop or 
            lemma in current_stopwords or 
            token.text.lower() in current_stopwords):
            continue
            
        # Include meaningful parts of speech
        if token.pos_ in ['NOUN', 'PROPN', 'ADJ', 'VERB']:
            # Additional filtering for verbs - keep only meaningful ones
            if token.pos_ == 'VERB':
                # Skip auxiliary and modal verbs
                if token.tag_ in ['MD', 'AUX'] or lemma in {'be', 'have', 'do', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can'}:
                    continue
                # Skip very common verbs unless they're domain-relevant
                common_verbs = {'say', 'tell', 'ask', 'give', 'take', 'put', 'get', 'make', 'go', 'come', 'see', 'look', 'know', 'think', 'want', 'need', 'try', 'use', 'find', 'keep', 'let', 'help', 'show', 'move', 'play', 'turn', 'start', 'stop', 'run', 'walk', 'sit', 'stand', 'hold', 'bring', 'leave', 'happen', 'become', 'seem', 'appear'}
                if lemma in common_verbs and lemma not in domain_terms:
                    continue
                    
            # Additional filtering for adjectives - keep descriptive ones
            if token.pos_ == 'ADJ':
                # Skip very basic adjectives unless domain-relevant
                basic_adjectives = {'good', 'bad', 'big', 'small', 'old', 'new', 'long', 'short', 'high', 'low', 'right', 'wrong', 'different', 'same', 'other', 'another', 'such', 'own', 'sure', 'able', 'free', 'full', 'hard', 'easy', 'clear', 'simple', 'real', 'true', 'false', 'open', 'close', 'ready', 'sorry', 'happy', 'sad'}
                if lemma in basic_adjectives and lemma not in domain_terms:
                    continue
                    
            # Skip single characters and numbers
            if len(lemma) == 1 or lemma.isdigit():
                continue
                
            # Skip if it's mostly punctuation
            if len([c for c in lemma if c.isalpha()]) < len(lemma) * 0.7:
                continue
                
            keywords.append(lemma)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_keywords = []
    for keyword in keywords:
        if keyword not in seen:
            seen.add(keyword)
            unique_keywords.append(keyword)
    
    return unique_keywords

@app.route('/admin/stats')
def admin_stats():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Total feedback count
    c.execute('SELECT COUNT(*) FROM feedback')
    total_feedback = c.fetchone()[0]
    
    # Unique visitors
    c.execute('SELECT COUNT(DISTINCT visitor_id) FROM feedback')
    unique_visitors = c.fetchone()[0]
    
    # Average words per feedback
    c.execute('SELECT content FROM feedback')
    all_content = [row[0] for row in c.fetchall()]
    avg_words = sum(len(content.split()) for content in all_content) / len(all_content) if all_content else 0
    
    # Project breakdown
    c.execute('SELECT project, COUNT(*) as count FROM feedback GROUP BY project ORDER BY count DESC')
    project_stats = [{'project': row[0], 'count': row[1]} for row in c.fetchall()]
    
    # Most active project
    most_active = project_stats[0]['project'] if project_stats else 'None'
    
    # Recent activity (last 24 hours)
    c.execute('SELECT COUNT(*) FROM feedback WHERE datetime(timestamp) > datetime("now", "-1 day")')
    recent_feedback = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_feedback': total_feedback,
        'unique_visitors': unique_visitors,
        'most_active_project': most_active,
        'avg_words': round(avg_words, 1),
        'project_stats': project_stats,
        'recent_feedback_24h': recent_feedback
    })

@app.route('/admin/export')
def admin_export():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    format_type = request.args.get('format', 'csv')
    project_filter = request.args.get('project', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Build query with filters
    query = 'SELECT project, content, timestamp, visitor_id FROM feedback WHERE 1=1'
    params = []
    
    if project_filter:
        query += ' AND project = ?'
        params.append(project_filter)
    
    if date_from:
        query += ' AND date(timestamp) >= ?'
        params.append(date_from)
    
    if date_to:
        query += ' AND date(timestamp) <= ?'
        params.append(date_to)
    
    query += ' ORDER BY timestamp'
    
    c.execute(query, params)
    data = c.fetchall()
    conn.close()
    
    if format_type == 'json':
        export_data = []
        for row in data:
            export_data.append({
                'project': row[0],
                'content': row[1],
                'timestamp': row[2],
                'visitor_id': row[3]
            })
        
        response = make_response(jsonify(export_data))
        response.headers['Content-Disposition'] = 'attachment; filename=feedback_export.json'
        response.headers['Content-Type'] = 'application/json'
        return response
    
    else:  # CSV
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Project', 'Content', 'Timestamp', 'Visitor ID'])
        
        # Write data with CSV injection protection
        for row in data:
            safe_row = [sanitize_csv_value(str(cell)) for cell in row]
            writer.writerow(safe_row)
        
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=feedback_export.csv'
        response.headers['Content-Type'] = 'text/csv'
        return response

@app.route('/admin/security/blocked_ips')
def admin_blocked_ips():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    current_time = time.time()
    blocked_ips = []
    
    for ip, block_time in ip_block_time.items():
        remaining_time = IP_BLOCK_DURATION - (current_time - block_time)
        if remaining_time > 0:
            blocked_ips.append({
                'ip': ip,
                'violations': ip_violations.get(ip, 0),
                'remaining_minutes': int(remaining_time / 60),
                'blocked_at': datetime.fromtimestamp(block_time).isoformat()
            })
    
    return jsonify({'blocked_ips': blocked_ips})

@app.route('/admin/security/block_ip', methods=['POST'])
def admin_block_ip():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    ip_to_block = data.get('ip')
    
    if not ip_to_block:
        return jsonify({'error': 'IP address required'}), 400
    
    # Validate IP format
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_to_block):
        return jsonify({'error': 'Invalid IP format'}), 400
    
    # Block the IP
    ip_block_time[ip_to_block] = time.time()
    ip_violations[ip_to_block] = IP_BLOCK_THRESHOLD
    
    return jsonify({'status': f'IP {ip_to_block} has been blocked'})

@app.route('/admin/security/recent_activity')
def admin_recent_activity():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get recent feedback with IP info (we don't store IPs, so this is limited)
    c.execute('''
        SELECT project, visitor_id, timestamp, 
               substr(content, 1, 50) as content_preview
        FROM feedback 
        WHERE datetime(timestamp) > datetime("now", "-2 hours")
        ORDER BY timestamp DESC 
        LIMIT 20
    ''')
    
    recent_activity = []
    for row in c.fetchall():
        recent_activity.append({
            'project': row[0],
            'visitor_id': row[1],
            'timestamp': row[2],
            'content_preview': row[3] + ('...' if len(row[3]) == 50 else ''),
            'type': 'feedback'
        })
    
    conn.close()
    
    # Add security events (violations, blocks)
    current_time = time.time()
    for ip, violations in ip_violations.items():
        if violations > 0:
            recent_activity.append({
                'ip': ip,
                'violations': violations,
                'type': 'security_violation',
                'timestamp': 'Recent'
            })
    
    return jsonify({'recent_activity': recent_activity[:20]})

@app.route('/admin/cleanup_duplicates', methods=['POST'])
def admin_cleanup_duplicates():
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Find duplicates based on content and project only (more aggressive)
        # This will catch traffic test duplicates with same content but different visitor_ids
        c.execute('''
            SELECT content, project, COUNT(*) as duplicate_count,
                   MIN(id) as keep_id, GROUP_CONCAT(id) as all_ids
            FROM feedback 
            GROUP BY content, project 
            HAVING COUNT(*) > 1
            ORDER BY duplicate_count DESC
        ''')
        
        duplicates = c.fetchall()
        
        if not duplicates:
            conn.close()
            return jsonify({
                'status': 'No duplicates found',
                'removed_count': 0,
                'duplicate_groups': 0
            })
        
        total_removed = 0
        duplicate_groups = len(duplicates)
        
        for content, project, dup_count, keep_id, all_ids in duplicates:
            # Parse the comma-separated IDs
            id_list = [int(id_str) for id_str in all_ids.split(',')]
            # Remove the ID we want to keep
            ids_to_remove = [id_val for id_val in id_list if id_val != keep_id]
            
            # Delete the duplicate entries
            for id_to_remove in ids_to_remove:
                c.execute('DELETE FROM feedback WHERE id = ?', (id_to_remove,))
                total_removed += 1
        
        # Also clean up duplicate visits
        c.execute('''
            DELETE FROM visits 
            WHERE id NOT IN (
                SELECT MIN(id) 
                FROM visits 
                GROUP BY project, visitor_id, date(timestamp)
            )
        ''')
        
        visits_removed = c.rowcount
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'Duplicates removed successfully',
            'removed_feedback_count': total_removed,
            'removed_visits_count': visits_removed,
            'duplicate_groups': duplicate_groups,
            'details': f'Removed {total_removed} duplicate feedback entries from {duplicate_groups} groups and {visits_removed} duplicate visits'
        })
        
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Cleanup failed: {str(e)}'}), 500

@app.route('/admin/compute_embeddings', methods=['POST'])
def admin_compute_embeddings():
    token = request.args.get('token')
    if not token or token != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    global embedding_model
    
    # Force reload the model if it's not available
    if embedding_model is None:
        print("Embedding model not loaded, attempting to load...")
        embedding_model = load_embedding_model()
    
    if embedding_model is None:
        return jsonify({'error': 'Embedding model not available. Please ensure sentence-transformers and torch are installed.'}), 500
    
    print("Embedding model is available, proceeding with computation...")
    
    data = request.json
    trajectory_type = data.get('type', 'project')  # 'project' or 'visitor'
    target_id = data.get('target_id')  # specific project or visitor, or 'all'
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Get data based on trajectory type and target
        if trajectory_type == 'project':
            if target_id and target_id != 'all':
                c.execute('SELECT project, content, timestamp, visitor_id FROM feedback WHERE project = ? ORDER BY timestamp', (target_id,))
                title = f"Project: {PROJECTS.get(target_id, {}).get('title', target_id)}"
            else:
                c.execute('SELECT project, content, timestamp, visitor_id FROM feedback ORDER BY timestamp')
                title = "All Projects"
        else:  # visitor
            if target_id and target_id != 'all':
                c.execute('SELECT project, content, timestamp, visitor_id FROM feedback WHERE visitor_id = ? ORDER BY timestamp', (target_id,))
                title = f"Visitor: {target_id}"
            else:
                # Get all visitors with multiple entries
                c.execute('SELECT project, content, timestamp, visitor_id FROM feedback WHERE visitor_id != "anonymous" ORDER BY timestamp')
                title = "All Visitors"
        
        all_data = c.fetchall()
        
        if len(all_data) < 3:
            conn.close()
            return jsonify({'error': 'Not enough data points for visualization (minimum 3 required)'}), 400
        
        print(f"Found {len(all_data)} feedback entries")
        
        # Prepare data
        all_texts = []
        text_metadata = []
        
        for project, content, timestamp, visitor_id in all_data:
            all_texts.append(content)
            text_metadata.append({
                'project': project,
                'timestamp': timestamp,
                'visitor_id': visitor_id
            })
        
        # Compute embeddings
        print(f"Computing embeddings for {len(all_texts)} texts...")
        try:
            embeddings = embedding_model.encode(all_texts, show_progress_bar=False)
            print(f"Embeddings computed successfully, shape: {embeddings.shape}")
        except Exception as e:
            conn.close()
            return jsonify({'error': f'Failed to compute embeddings: {str(e)}'}), 500
        
        # Apply UMAP with safer parameters
        print("Applying UMAP dimensionality reduction...")
        try:
            n_neighbors = min(5, len(embeddings) - 1)
            umap_reducer = umap.UMAP(
                n_components=2, 
                random_state=42, 
                n_neighbors=n_neighbors,
                min_dist=0.1,
                metric='cosine'
            )
            umap_embeddings = umap_reducer.fit_transform(embeddings)
            print(f"UMAP completed successfully, shape: {umap_embeddings.shape}")
        except Exception as e:
            conn.close()
            return jsonify({'error': f'UMAP failed: {str(e)}'}), 500
        
        # Create minimalistic Plotly visualization
        print("Creating visualization...")
        try:
            fig = go.Figure()
            
            if trajectory_type == 'project':
                # Group by project
                unique_projects = list(set(meta['project'] for meta in text_metadata))
                colors = px.colors.qualitative.Set3[:len(unique_projects)]
                
                for i, project in enumerate(unique_projects):
                    project_indices = [j for j, meta in enumerate(text_metadata) if meta['project'] == project]
                    project_coords = umap_embeddings[project_indices]
                    
                    # Add scatter points
                    fig.add_trace(go.Scatter(
                        x=project_coords[:, 0],
                        y=project_coords[:, 1],
                        mode='markers+lines',
                        name=project,
                        marker=dict(
                            size=8,
                            color=colors[i % len(colors)],
                            opacity=0.8,
                            line=dict(width=1, color='white')
                        ),
                        line=dict(
                            width=2,
                            color=colors[i % len(colors)],
                            dash='dot'
                        ),
                        hovertemplate='<b>%{fullData.name}</b><br>Point %{pointNumber}<extra></extra>'
                    ))
            else:
                # Group by visitor
                visitor_counts = defaultdict(int)
                for meta in text_metadata:
                    visitor_counts[meta['visitor_id']] += 1
                
                # Only show visitors with multiple entries
                multi_entry_visitors = [v for v, count in visitor_counts.items() if count > 1]
                colors = px.colors.qualitative.Pastel[:len(multi_entry_visitors)]
                
                for i, visitor in enumerate(multi_entry_visitors):
                    visitor_indices = [j for j, meta in enumerate(text_metadata) if meta['visitor_id'] == visitor]
                    visitor_coords = umap_embeddings[visitor_indices]
                    
                    # Add scatter points with trajectory
                    fig.add_trace(go.Scatter(
                        x=visitor_coords[:, 0],
                        y=visitor_coords[:, 1],
                        mode='markers+lines',
                        name=visitor,
                        marker=dict(
                            size=6,
                            color=colors[i % len(colors)],
                            opacity=0.9,
                            line=dict(width=1, color='rgba(255,255,255,0.3)')
                        ),
                        line=dict(
                            width=1.5,
                            color=colors[i % len(colors)],
                            smoothing=1.3
                        ),
                        hovertemplate='<b>%{fullData.name}</b><br>Entry %{pointNumber}<extra></extra>'
                    ))
            
            # Minimalistic styling with better visibility
            fig.update_layout(
                title=dict(
                    text=f'UMAP Trajectories: {title}',
                    font=dict(size=16, color='#333333', family='Inter, system-ui, sans-serif'),
                    x=0.5
                ),
                xaxis=dict(
                    title=dict(
                        text='Semantic Dimension 1',
                        font=dict(size=12, color='#666666')
                    ),
                    showgrid=True,
                    gridcolor='rgba(200,200,200,0.3)',
                    zeroline=False,
                    showticklabels=True,
                    tickfont=dict(size=10, color='#666666')
                ),
                yaxis=dict(
                    title=dict(
                        text='Semantic Dimension 2',
                        font=dict(size=12, color='#666666')
                    ),
                    showgrid=True,
                    gridcolor='rgba(200,200,200,0.3)',
                    zeroline=False,
                    showticklabels=True,
                    tickfont=dict(size=10, color='#666666')
                ),
                plot_bgcolor='rgba(255,255,255,0.95)',
                paper_bgcolor='rgba(255,255,255,1)',
                font=dict(family='Inter, system-ui, sans-serif', color='#333333'),
                legend=dict(
                    bgcolor='rgba(255,255,255,0.9)',
                    bordercolor='rgba(200,200,200,0.5)',
                    borderwidth=1,
                    font=dict(size=10, color='#333333')
                ),
                margin=dict(l=60, r=40, t=80, b=60),
                width=800,
                height=600,
                showlegend=True
            )
            
            # Convert to JSON for frontend
            plot_json = json.dumps(fig, cls=PlotlyJSONEncoder)
            print(f"Plot JSON length: {len(plot_json)}")
            print(f"Plot JSON preview: {plot_json[:200]}...")
            
            print("Visualization created successfully")
            
        except Exception as e:
            conn.close()
            return jsonify({'error': f'Visualization failed: {str(e)}'}), 500
        
        # Prepare response data
        trajectory_data = []
        for i, (text, meta) in enumerate(zip(all_texts, text_metadata)):
            trajectory_data.append({
                'index': i + 1,
                'text': text[:100] + '...' if len(text) > 100 else text,
                'full_text': text,
                'timestamp': meta['timestamp'],
                'umap_x': float(umap_embeddings[i, 0]),
                'umap_y': float(umap_embeddings[i, 1]),
                'project': meta['project'],
                'visitor_id': meta['visitor_id']
            })
        
        result = {
            'success': True,
            'trajectory_type': trajectory_type,
            'target_id': target_id,
            'title': title,
            'plot_json': plot_json,
            'data_points': len(trajectory_data),
            'trajectory_data': trajectory_data
        }
        
        conn.close()
        print("UMAP computation completed successfully")
        return jsonify(result)
        
    except Exception as e:
        conn.close()
        print(f"Unexpected error in compute_embeddings: {str(e)}")
        return jsonify({'error': f'Computation failed: {str(e)}'}), 500

@app.route('/api/exquisite_corpse')
def get_exquisite_corpse():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content, project, timestamp FROM feedback ORDER BY timestamp DESC LIMIT 50')
    feedback_data = [{'content': row[0], 'project': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    conn.close()

    if len(feedback_data) < 3:
        return jsonify({'fragments': [], 'poem': 'Waiting for thoughts to emerge...'})

    # Generate creative fragments using language manipulation
    fragments = generate_poetic_fragments(feedback_data)
    
    # Create an exquisite corpse poem
    poem = create_exquisite_corpse_poem(fragments)
    
    return jsonify({
        'fragments': fragments,
        'poem': poem,
        'metadata': {
            'source_count': len(feedback_data),
            'generation_time': datetime.now().isoformat()
        }
    })

@app.route('/api/trace/<visitor_id>')
def get_trace(visitor_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get visits
    c.execute('SELECT project, timestamp FROM visits WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    visits = [{'project': row[0], 'timestamp': row[1]} for row in c.fetchall()]
    
    # Get feedback with IDs for deletion
    c.execute('SELECT id, project, content, timestamp FROM feedback WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    feedback = [{'id': row[0], 'project': row[1], 'content': row[2], 'timestamp': row[3]} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({'visits': visits, 'feedback': feedback})

@app.route('/api/feedback/<visitor_id>/<int:feedback_id>', methods=['DELETE'])
def delete_feedback(visitor_id, feedback_id):
    """Delete a specific feedback entry for a visitor."""
    ip = request.remote_addr
    
    # Validate visitor_id
    is_valid, err_msg = validate_visitor_id(visitor_id)
    if not is_valid:
        ip_violations[ip] += 1
        return jsonify({'error': err_msg}), 400
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Verify the feedback belongs to this visitor before deleting
    c.execute('SELECT id FROM feedback WHERE id = ? AND visitor_id = ?', (feedback_id, visitor_id))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Feedback not found or access denied'}), 404
    
    # Delete the feedback
    c.execute('DELETE FROM feedback WHERE id = ? AND visitor_id = ?', (feedback_id, visitor_id))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'deleted'})

@app.route('/admin/feedback/<int:feedback_id>', methods=['DELETE'])
def admin_delete_feedback(feedback_id):
    """Admin endpoint to delete any feedback entry."""
    if request.args.get('token') != ADMIN_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Check if feedback exists
    c.execute('SELECT id FROM feedback WHERE id = ?', (feedback_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Feedback not found'}), 404
    
    # Delete the feedback
    c.execute('DELETE FROM feedback WHERE id = ?', (feedback_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'deleted'})

@app.route('/api/personal_corpse/<visitor_id>')
def get_personal_corpse(visitor_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content, project, timestamp FROM feedback WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    feedback_data = [{'content': row[0], 'project': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    conn.close()

    if len(feedback_data) < 2:
        return jsonify({
            'fragments': [], 
            'poem': 'Your thoughts are still\nforming in the digital\nether...',
            'metadata': {'source_count': len(feedback_data)}
        })

    # Generate personal fragments using the same creative manipulation
    fragments = generate_poetic_fragments(feedback_data)
    
    # Create a more personal, intimate poem structure
    poem = create_personal_corpse_poem(fragments, visitor_id)
    
    return jsonify({
        'fragments': fragments,
        'poem': poem,
        'metadata': {
            'source_count': len(feedback_data),
            'generation_time': datetime.now().isoformat(),
            'visitor_id': visitor_id
        }
    })

@socketio.on('connect')
def handle_connect():
    global active_visitors
    active_visitors += 1
    print(f'Client connected. Active presences: {active_visitors}')
    socketio.emit('update_visitor_count', {'count': active_visitors})

def generate_poetic_fragments(feedback_data):
    """Generate poetic fragments through enhanced creative language manipulation."""
    fragments = []
    
    for entry in feedback_data:
        text = entry['content']
        project = entry['project']
        
        try:
            # Detect language for processing
            lang = detect(text)
        except LangDetectException:
            lang = 'en'
        
        nlp = nlp_fr if lang == 'fr' else nlp_en
        doc = nlp(text)
        
        # Extract different types of poetic elements with enhanced filtering
        
        # 1. Emotional phrases (meaningful noun chunks with descriptive elements)
        emotional_phrases = []
        for chunk in doc.noun_chunks:
            chunk_text = chunk.text.lower().strip()
            # Filter out generic phrases
            if (len(chunk.text.split()) <= 4 and 
                len(chunk_text) > 5 and
                not any(generic in chunk_text for generic in ['this thing', 'that thing', 'the way', 'the time', 'the work'])):
                # Check if it contains meaningful adjectives or descriptive nouns
                has_meaningful_content = any(token.pos_ in ['ADJ', 'NOUN'] and 
                                           not token.is_stop and 
                                           len(token.lemma_) > 3 
                                           for token in chunk)
                if has_meaningful_content:
                    emotional_phrases.append(chunk_text)
        
        # 2. Action fragments (meaningful verb phrases)
        action_fragments = []
        for token in doc:
            if (token.pos_ == 'VERB' and 
                not token.is_stop and 
                token.lemma_ not in ['be', 'have', 'do', 'get', 'make', 'go', 'come', 'see', 'know', 'think']):
                
                # Build verb phrase with meaningful context
                verb_phrase = []
                
                # Add meaningful adverbs or particles
                for child in token.children:
                    if (child.pos_ in ['ADV', 'PART'] and 
                        not child.is_stop and 
                        len(child.text) > 2):
                        verb_phrase.append(child.text.lower())
                
                verb_phrase.append(token.lemma_.lower())
                
                # Add meaningful objects or complements
                for child in token.children:
                    if (child.pos_ in ['NOUN', 'PROPN'] and 
                        not child.is_stop and 
                        len(child.text) > 3):
                        verb_phrase.append(child.text.lower())
                        break  # Only add one object to keep it concise
                
                if len(verb_phrase) <= 4 and len(' '.join(verb_phrase)) > 4:
                    action_fragments.append(' '.join(verb_phrase))
        
        # 3. Enhanced conceptual bridges (domain-relevant meaningful words)
        concepts = []
        processed_keywords = process_text_bilingual(text)
        
        # Prioritize domain-specific and emotionally resonant concepts
        priority_concepts = []
        regular_concepts = []
        
        for keyword in processed_keywords:
            # Check if it's a high-value concept for art/tech context
            if any(domain_term in keyword for domain_term in [
                'ai', 'artificial', 'machine', 'digital', 'virtual', 'reality',
                'human', 'emotion', 'feeling', 'experience', 'consciousness',
                'art', 'creative', 'aesthetic', 'beauty', 'expression',
                'technology', 'interaction', 'interface', 'connection',
                'future', 'memory', 'dream', 'imagination', 'transformation'
            ]):
                priority_concepts.append(keyword)
            elif len(keyword) > 4:  # Longer words tend to be more specific
                regular_concepts.append(keyword)
        
        # Combine with priority given to domain concepts
        concepts = priority_concepts[:3] + regular_concepts[:2]
        
        # 4. Enhanced surreal combinations (meaningful unexpected pairings)
        surreal_pairs = []
        meaningful_tokens = [t for t in doc if (
            not t.is_stop and 
            t.pos_ in ['NOUN', 'ADJ', 'VERB'] and 
            len(t.lemma_) > 3 and
            t.lemma_.lower() not in ['thing', 'way', 'time', 'work', 'make', 'get', 'go', 'see', 'know']
        )]
        
        for i in range(len(meaningful_tokens) - 1):
            token1, token2 = meaningful_tokens[i], meaningful_tokens[i+1]
            # Create surreal pairs from different parts of speech
            if (token1.pos_ != token2.pos_ and 
                not (token1.pos_ == 'VERB' and token2.pos_ == 'NOUN')):  # Avoid common verb-noun pairs
                pair = f"{token1.lemma_.lower()} {token2.lemma_.lower()}"
                if len(pair) > 8:  # Ensure meaningful length
                    surreal_pairs.append(pair)
        
        # Add fragments with enhanced filtering
        for phrase in emotional_phrases[:2]:
            if len(phrase) > 6:  # Ensure substantial content
                fragments.append({
                    'text': phrase,
                    'type': 'emotional',
                    'project': project,
                    'source': 'visitor reflection'
                })
        
        for action in action_fragments[:2]:
            if len(action) > 4:
                fragments.append({
                    'text': action,
                    'type': 'action',
                    'project': project,
                    'source': 'visitor reflection'
                })
        
        for concept in concepts[:3]:
            if len(concept) > 3:
                fragments.append({
                    'text': concept,
                    'type': 'concept',
                    'project': project,
                    'source': 'visitor reflection'
                })
        
        for pair in surreal_pairs[:2]:
            if len(pair) > 8:
                fragments.append({
                    'text': pair,
                    'type': 'surreal',
                    'project': project,
                    'source': 'visitor reflection'
                })
    
    # Enhanced filtering and shuffling
    import random
    
    # Remove duplicates while preserving variety
    unique_fragments = []
    seen_texts = set()
    
    for fragment in fragments:
        if fragment['text'] not in seen_texts:
            seen_texts.add(fragment['text'])
            unique_fragments.append(fragment)
    
    # Shuffle and ensure good type distribution
    random.shuffle(unique_fragments)
    
    # Ensure we have a good mix of fragment types
    type_counts = {'emotional': 0, 'action': 0, 'concept': 0, 'surreal': 0}
    balanced_fragments = []
    
    for fragment in unique_fragments:
        ftype = fragment['type']
        if type_counts[ftype] < 8:  # Max 8 of each type
            balanced_fragments.append(fragment)
            type_counts[ftype] += 1
        
        if len(balanced_fragments) >= 30:
            break
    
    return balanced_fragments

def create_exquisite_corpse_poem(fragments):
    """Create a surreal exquisite corpse poem from fragments, avoiding repetition and improving flow."""
    if len(fragments) < 5:
        return "In the space between\nthoughts gather\nlike digital moths\nseeking light"
    
    import random
    
    # Group fragments by type and shuffle them to ensure variety
    emotional = [f for f in fragments if f['type'] == 'emotional']
    random.shuffle(emotional)
    actions = [f for f in fragments if f['type'] == 'action']
    random.shuffle(actions)
    concepts = [f for f in fragments if f['type'] == 'concept']
    random.shuffle(concepts)
    surreal = [f for f in fragments if f['type'] == 'surreal']
    random.shuffle(surreal)
    
    used_keywords = set()
    
    # Helper to get a fragment's text, avoiding keyword repetition
    def get_fragment_text(fragment_list):
        nonlocal used_keywords
        if not fragment_list:
            return None

        # Try to find a fragment with no overlapping keywords
        for i, fragment in enumerate(fragment_list):
            fragment_keywords = {w for w in fragment['text'].lower().split() if len(w) > 3}
            if not (fragment_keywords & used_keywords):
                selected_fragment = fragment_list.pop(i)
                used_keywords.update(fragment_keywords)
                return selected_fragment['text']
        
        # If all remaining fragments have overlaps, just pick the first one
        selected_fragment = fragment_list.pop(0)
        fragment_keywords = {w for w in selected_fragment['text'].lower().split() if len(w) > 3}
        used_keywords.update(fragment_keywords)
        return selected_fragment['text']

    poem_lines = []
    
    # --- Stanza 1: Opening ---
    opening_text = get_fragment_text(emotional)
    if opening_text:
        # Clean fragment to avoid double articles like "the the"
        if opening_text.lower().startswith(('the ', 'a ', 'an ')):
            opening_text = ' '.join(opening_text.split()[1:])
        poem_lines.append(f"In the {opening_text}")
    else:
        poem_lines.append("In the space between")
    
    # --- Stanza 2: Action/State with varied transitions ---
    action_text = get_fragment_text(actions)
    if action_text:
        transition = random.choice(["where", "which reveals", "that wants to"])
        poem_lines.append(f"{transition} {action_text}")
    else:
        concept_text = get_fragment_text(concepts)
        if concept_text:
            poem_lines.append(f"where {concept_text} dwells")
    
    # --- Stanza 3: Surreal Turn with varied structure ---
    surreal_text = get_fragment_text(surreal)
    if surreal_text:
        structure = random.choice([
            lambda s: s,
            lambda s: f"a dream of {s}",
            lambda s: f"an echo of {s}"
        ])
        poem_lines.append(structure(surreal_text))
    else:
        c1 = get_fragment_text(concepts)
        c2 = get_fragment_text(concepts)
        if c1 and c2:
            poem_lines.append(f"{c1} becomes {c2}")
    
    # --- Stanza 4: Conceptual Bridge ---
    bridge_text = get_fragment_text(concepts)
    if bridge_text:
        poem_lines.append(f"a whisper of {bridge_text}")

    # --- Stanza 5: Closing with varied transitions ---
    closing_emotional_text = get_fragment_text(emotional)
    if closing_emotional_text:
        transition = random.choice(["dissolves into", "leaving only", "becoming"])
        poem_lines.append(f"{transition} {closing_emotional_text}")
    else:
        closing_action_text = get_fragment_text(actions)
        if closing_action_text:
            poem_lines.append(f"and continues to {closing_action_text}")
        else:
            poem_lines.append("an echo in the machine")
    
    # Filter out empty lines that might result from missing fragments
    final_poem_lines = [line for line in poem_lines if line and line.strip()]
    
    return '\n'.join(final_poem_lines)

def create_personal_corpse_poem(fragments, visitor_id):
    """Create a personal, intimate exquisite corpse poem from individual's fragments."""
    if len(fragments) < 3:
        return f"Your thoughts drift\nthrough digital space\nwaiting to become\nsomething more"
    
    import random
    
    # Group fragments by type
    emotional = [f for f in fragments if f['type'] == 'emotional']
    actions = [f for f in fragments if f['type'] == 'action']
    concepts = [f for f in fragments if f['type'] == 'concept']
    surreal = [f for f in fragments if f['type'] == 'surreal']
    
    # Create more personal, introspective poem structure
    poem_lines = []
    
    # Personal opening - more intimate
    personal_openings = [
        "You entered seeking",
        "Your mind wandered through",
        "In your reflection",
        "You discovered",
        "Your thoughts became"
    ]
    
    if emotional:
        poem_lines.append(f"{random.choice(personal_openings)} {random.choice(emotional)['text']}")
    elif concepts:
        poem_lines.append(f"{random.choice(personal_openings)} {random.choice(concepts)['text']}")
    else:
        poem_lines.append(f"{random.choice(personal_openings)} something unnamed")
    
    # Personal action/transformation
    if actions:
        poem_lines.append(f"and began to {random.choice(actions)['text']}")
    elif surreal:
        poem_lines.append(f"and felt {random.choice(surreal)['text']}")
    elif concepts:
        poem_lines.append(f"and touched {random.choice(concepts)['text']}")
    
    # Middle - the encounter
    if surreal and concepts:
        poem_lines.append(f"where {random.choice(surreal)['text']} meets {random.choice(concepts)['text']}")
    elif emotional and len(emotional) > 1:
        e1, e2 = random.sample(emotional, 2)
        poem_lines.append(f"between {e1['text']} and {e2['text']}")
    elif concepts and len(concepts) > 1:
        c1, c2 = random.sample(concepts, 2)
        poem_lines.append(f"as {c1['text']} transforms into {c2['text']}")
    else:
        poem_lines.append("in the liminal space")
    
    # Personal resolution - what remains
    personal_endings = [
        "Now you carry",
        "You leave with",
        "Your trace remains as",
        "You become",
        "In you lives"
    ]
    
    if concepts:
        poem_lines.append(f"{random.choice(personal_endings)} {random.choice(concepts)['text']}")
    elif emotional:
        poem_lines.append(f"{random.choice(personal_endings)} {random.choice(emotional)['text']}")
    else:
        poem_lines.append(f"{random.choice(personal_endings)} the memory of encounter")
    
    return '\n'.join(poem_lines)

@socketio.on('disconnect')
def handle_disconnect():
    global active_visitors
    if active_visitors > 0:
        active_visitors -= 1
    print(f'Client disconnected. Active presences: {active_visitors}')
    socketio.emit('update_visitor_count', {'count': active_visitors})

