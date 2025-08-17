from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import sqlite3
import os
import json
from collections import Counter
import re
from datetime import datetime
import numpy as np
import spacy
from itertools import combinations
from langdetect import detect, LangDetectException

# Load spacy models
try:
    nlp_en = spacy.load('en_core_web_sm')
    nlp_fr = spacy.load('fr_core_news_sm')
except OSError:
    print('Language models not found. Please run:')
    print('python -m spacy download en_core_web_sm')
    print('python -m spacy download fr_core_news_sm')
    exit()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'machinic-encounters-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

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

# Project data extracted from exhibition materials
PROJECTS = {
    'catherine': {
        'title': 'The space between two things is a portal',
        'artist': 'Catherine Lejeune',
        'desc': 'A meditation on human-machine intimacy, absence, and the grief of unmet expectations. Through video and sculpture, the work reflects on coded obedience, resistance, and the strange beauty of fugitive forms of life.',
        'vibe': 'intimate, melancholic, resistant',
        'thumb': 'catherine.png',
        'position': {'x': 45, 'y': 50}
    },
    'george': {
        'title': 'Archive of Belonging',
        'artist': 'George Kerasias',
        'desc': 'An AI-powered interactive installation disguised as a fictional immigration booth. Participants are evaluated against fabricated civic metrics in this cinematic, satirical challenge to bureaucratic truth-making.',
        'vibe': 'cinematic, satirical, challenging',
        'thumb': 'george.png',
        'position': {'x': 75, 'y': 75}
    },
    'lydia': {
        'title': 'Florilegi/o',
        'artist': 'Lydia Graveline & Louis Barbier',
        'desc': 'An interactive archive of speculative digitized flowers. Each bloom began as organic matter, then reimagined through AI processes. A retrofuture encyclopedia of what won\'t be.',
        'vibe': 'retrofuture, encyclopedic, nostalgic',
        'thumb': 'lydiaandlouis.png',
        'position': {'x': 35, 'y': 25}
    },
    'mike_kris': {
        'title': 'Templum: Emergence as divination',
        'artist': 'Mike Cassidy & Kristian North',
        'desc': 'Ancient augury meets AI. A platform for paradivination using obsolescing tech, presenting as an educational game and digital anarchive of ecological attunement.',
        'vibe': 'ancient, mystical, deep',
        'thumb': 'krisandmike.png',
        'position': {'x': 65, 'y': 25}
    },
    'nata': {
        'title': 'The Feeling of Thought',
        'artist': 'Nata Pavlik & Jihane Mossalim',
        'desc': 'A perceptually grounded language model training interface examining how language moves through perception and relation. Understanding aphantasia to transcend the Turing test.',
        'vibe': 'perceptual, kinetic, transcendent',
        'thumb': 'nataandjihane.png',
        'position': {'x': 20, 'y': 75}
    },
    'poki': {
        'title': 'Big Brother',
        'artist': 'Poki Chan & Karim Nafiz',
        'desc': 'A surveillance LLM trained to monitor conversations for dissent. Participants must express restricted ideas through coded language without detection.',
        'vibe': 'surveillance, coded, experimental',
        'thumb': 'pokiandkarim.png',
        'position': {'x': 45, 'y': 75}
    },
    'kamyar': {
        'title': 'Dreaming Impermanence',
        'artist': 'Kamyar Karimi',
        'desc': 'A meditation on control and temporality through maps and AI dreams. Inspired by Borges\' "On the Exactitude of Science" in our age of cybernetics.',
        'vibe': 'meditative, temporal, cartographic',
        'thumb': 'kamyar.png',
        'position': {'x': 65, 'y': 50}
    },
    'aurelie': {
        'title': 'Black Pudding: Collaborative Speculation Workshop',
        'artist': 'Aurélie Petit',
        'desc': 'A workshop offering an accessible entry point into creative AI re-use through collaborative animation and custom dataset creation using collages.',
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
    return render_template('index.html', projects=PROJECTS)

@app.route('/project/<name>')
def project(name):
    proj = PROJECTS.get(name, {"title": "Unknown", "desc": "", "thumb": "", "artist": ""})
    return render_template('project.html', project=proj, project_id=name)

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
    
    if project and content:
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
    return jsonify({"status": "error"}), 400

@app.route('/visit', methods=['POST'])
def visit():
    data = request.json
    project = data.get('project')
    visitor_id = data.get('visitor_id', 'anonymous')
    
    if project:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('INSERT INTO visits (project, visitor_id) VALUES (?, ?)', 
                 (project, visitor_id))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 400

@app.route('/api/wordcloud')
def get_wordcloud():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content FROM feedback')
    texts = [row[0] for row in c.fetchall()]
    conn.close()
    
    # Simple word frequency
    words = []
    for text in texts:
        words.extend(re.findall(r'\b\w+\b', text.lower()))
    
    word_freq = Counter(words)
    # Filter out common words
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'}
    
    filtered_words = {word: freq for word, freq in word_freq.items() 
                     if word not in stop_words and len(word) > 2}
    
    return jsonify(filtered_words)

def process_text_bilingual(text):
    """Detects language and extracts keywords using the appropriate model."""
    try:
        lang = detect(text)
    except LangDetectException:
        lang = 'en' # Default to English if detection fails

    nlp = nlp_fr if lang == 'fr' else nlp_en

    doc = nlp(text)
    keywords = [
        token.lemma_.lower() for token in doc 
        if token.pos_ in ['NOUN', 'PROPN', 'ADJ', 'VERB'] 
        and not token.is_stop 
        and len(token.lemma_) > 2
    ]
    return list(set(keywords))

@app.route('/api/word_network')
def get_word_network():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content FROM feedback')
    texts = [row[0] for row in c.fetchall()]
    conn.close()

    if len(texts) < 2:
        return jsonify({'nodes': [], 'links': []})

    # Process texts to extract meaningful keywords bilingually
    keyword_docs = [process_text_bilingual(text) for text in texts]
    word_freq = Counter(keyword for doc in keyword_docs for keyword in doc)

    # Calculate co-occurrence
    co_occurrence = Counter()
    for doc in keyword_docs:
        # Get all pairs of keywords in the doc
        for w1, w2 in combinations(doc, 2):
            # Sort to ensure (w1, w2) is the same as (w2, w1)
            pair = tuple(sorted((w1, w2)))
            co_occurrence[pair] += 1

    if not word_freq:
        return jsonify({'nodes': [], 'links': []})

    # Select top words for the network
    top_words = {word for word, freq in word_freq.most_common(30)}

    nodes = [{'id': word, 'frequency': word_freq[word], 'size': 12 + word_freq[word] * 5} for word in top_words]

    links = []
    for (w1, w2), weight in co_occurrence.items():
        if w1 in top_words and w2 in top_words and weight > 0:
            links.append({
                'source': w1,
                'target': w2,
                'strength': weight
            })

    return jsonify({'nodes': nodes, 'links': links})

@app.route('/api/trace/<visitor_id>')
def get_trace(visitor_id):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get visits
    c.execute('SELECT project, timestamp FROM visits WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    visits = [{'project': row[0], 'timestamp': row[1]} for row in c.fetchall()]
    
    # Get feedback
    c.execute('SELECT project, content, timestamp FROM feedback WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    feedback = [{'project': row[0], 'content': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({'visits': visits, 'feedback': feedback})

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
