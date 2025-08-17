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
        'artist': 'Caterine Lejeune',
        'desc': 'A meditation on human-machine intimacy, absence, and the grief of unmet expectations. Through video and sculpture, the work reflects on coded obedience, resistance, and the strange beauty of fugitive forms of life.',
        'vibe': 'intimate, melancholic, resistant',
        'thumb': 'caterine.png',
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
    return jsonify({"status": "error"}), 400

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

@app.route('/api/word_network')
def get_word_network():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT content, project, timestamp FROM feedback ORDER BY timestamp')
    feedback_data = [{'content': row[0], 'project': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    conn.close()

    if len(feedback_data) < 2:
        return jsonify({'nodes': [], 'links': [], 'metadata': {'total_feedback': 0}})

    # Extract concepts with project context
    all_concepts = []
    project_concepts = {}
    concept_projects = {}
    
    for entry in feedback_data:
        concepts = process_text_bilingual(entry['content'])
        all_concepts.extend(concepts)
        
        # Track which projects each concept appears in
        for concept in concepts:
            if concept not in concept_projects:
                concept_projects[concept] = set()
            concept_projects[concept].add(entry['project'])
        
        # Track concepts per project
        if entry['project'] not in project_concepts:
            project_concepts[entry['project']] = []
        project_concepts[entry['project']].extend(concepts)

    concept_freq = Counter(all_concepts)
    if not concept_freq:
        return jsonify({'nodes': [], 'links': [], 'metadata': {'total_feedback': len(feedback_data)}})

    # Select top concepts
    top_concepts = {concept for concept, freq in concept_freq.most_common(35)}
    
    # Calculate enhanced relationships
    relationships = []
    
    # 1. Traditional co-occurrence within same feedback
    co_occurrence = Counter()
    for entry in feedback_data:
        concepts = [c for c in process_text_bilingual(entry['content']) if c in top_concepts]
        for c1, c2 in combinations(concepts, 2):
            pair = tuple(sorted((c1, c2)))
            co_occurrence[pair] += 1
    
    # 2. Cross-project conceptual bridges (concepts that appear in multiple projects)
    cross_project_strength = {}
    for concept in top_concepts:
        projects_with_concept = concept_projects.get(concept, set())
        if len(projects_with_concept) > 1:
            # This concept bridges multiple projects
            for other_concept in top_concepts:
                if other_concept != concept:
                    other_projects = concept_projects.get(other_concept, set())
                    shared_projects = projects_with_concept & other_projects
                    if shared_projects:
                        pair = tuple(sorted((concept, other_concept)))
                        cross_project_strength[pair] = len(shared_projects)
    
    # 3. Semantic clustering based on project co-occurrence
    project_semantic_links = Counter()
    for project, concepts in project_concepts.items():
        project_concepts_filtered = [c for c in concepts if c in top_concepts]
        for c1, c2 in combinations(set(project_concepts_filtered), 2):
            pair = tuple(sorted((c1, c2)))
            project_semantic_links[pair] += 1
    
    # Combine all relationship types
    all_pairs = set(co_occurrence.keys()) | set(cross_project_strength.keys()) | set(project_semantic_links.keys())
    
    for pair in all_pairs:
        c1, c2 = pair
        
        # Calculate composite strength
        cooccur_strength = co_occurrence.get(pair, 0)
        bridge_strength = cross_project_strength.get(pair, 0) * 2  # Boost cross-project links
        semantic_strength = project_semantic_links.get(pair, 0)
        
        total_strength = cooccur_strength + bridge_strength + semantic_strength
        
        if total_strength > 0:
            # Determine link type
            if bridge_strength > cooccur_strength and bridge_strength > semantic_strength:
                link_type = 'bridge'
            elif semantic_strength > cooccur_strength:
                link_type = 'semantic'
            else:
                link_type = 'cooccurrence'
            
            relationships.append({
                'source': c1,
                'target': c2,
                'strength': min(total_strength, 8),  # Cap for visualization
                'type': link_type,
                'projects': list(concept_projects.get(c1, set()) & concept_projects.get(c2, set()))
            })

    # Create enhanced nodes
    nodes = []
    for concept in top_concepts:
        projects_list = list(concept_projects.get(concept, set()))
        node_type = 'bridge' if len(projects_list) > 2 else 'local'
        
        nodes.append({
            'id': concept,
            'frequency': concept_freq[concept],
            'size': 10 + min(concept_freq[concept] * 3, 20),
            'type': node_type,
            'projects': projects_list,
            'cross_project_score': len(projects_list)
        })

    return jsonify({
        'nodes': nodes,
        'links': relationships,
        'metadata': {
            'total_feedback': len(feedback_data),
            'unique_concepts': len(top_concepts),
            'cross_project_bridges': len([n for n in nodes if n['type'] == 'bridge']),
            'projects': list(project_concepts.keys())
        }
    })

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
    
    # Get feedback
    c.execute('SELECT project, content, timestamp FROM feedback WHERE visitor_id = ? ORDER BY timestamp', (visitor_id,))
    feedback = [{'project': row[0], 'content': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({'visits': visits, 'feedback': feedback})

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
    print('Client connected')

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
    """Create a surreal exquisite corpse poem from fragments."""
    if len(fragments) < 5:
        return "In the space between\nthoughts gather\nlike digital moths\nseeking light"
    
    import random
    
    # Group fragments by type
    emotional = [f for f in fragments if f['type'] == 'emotional']
    actions = [f for f in fragments if f['type'] == 'action']
    concepts = [f for f in fragments if f['type'] == 'concept']
    surreal = [f for f in fragments if f['type'] == 'surreal']
    
    # Create poem structure with surreal logic
    poem_lines = []
    
    # Opening line - set the scene
    if emotional:
        poem_lines.append(f"In the {random.choice(emotional)['text']}")
    else:
        poem_lines.append("In the space between")
    
    # Action line
    if actions:
        poem_lines.append(f"where {random.choice(actions)['text']}")
    elif concepts:
        poem_lines.append(f"where {random.choice(concepts)['text']} dwells")
    
    # Surreal middle
    if surreal:
        poem_lines.append(f"{random.choice(surreal)['text']}")
    elif concepts and len(concepts) > 1:
        c1, c2 = random.sample(concepts, 2)
        poem_lines.append(f"{c1['text']} becomes {c2['text']}")
    
    # Conceptual bridge
    if concepts:
        poem_lines.append(f"and {random.choice(concepts)['text']}")
    
    # Closing - return to emotion or action
    if emotional and len(emotional) > 1:
        closing = random.choice([f for f in emotional if f != emotional[0]])
        poem_lines.append(f"dissolves into {closing['text']}")
    elif actions:
        poem_lines.append(f"continues to {random.choice(actions)['text']}")
    else:
        poem_lines.append("echoes in the machine")
    
    return '\n'.join(poem_lines)

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
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
