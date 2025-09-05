# INTENTIONALLY INSECURE – FOR LOCAL TESTING ONLY

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_cors import CORS
import sqlite3
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['DEBUG'] = True

# Enable CORS for all routes
CORS(app)

# Database path
DB_PATH = 'lab.db'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Index page with links to all vulnerable endpoints"""
    return render_template('index.html')

@app.route('/healthz')
def healthz():
    """Health check endpoint"""
    return jsonify({"ok": True})

# XSS - Reflected vulnerabilities
@app.route('/search')
def search():
    """XSS reflected - html_text context"""
    q = request.args.get('q', '')
    return render_template('search.html', query=q)

@app.route('/profile')
def profile():
    """XSS reflected - attr context"""
    name = request.args.get('name', '')
    return render_template('profile.html', name=name)

@app.route('/script')
def script():
    """XSS reflected - js_string context"""
    msg = request.args.get('msg', '')
    return render_template('script.html', message=msg)

# XSS - Stored vulnerabilities
@app.route('/notes', methods=['GET', 'POST'])
def notes():
    """XSS stored - unsanitized content"""
    if request.method == 'POST':
        content = request.form.get('content', '')
        conn = get_db_connection()
        conn.execute("INSERT INTO notes (content) VALUES (?)", (content,))
        conn.commit()
        conn.close()
        return redirect(url_for('notes'))
    
    # GET - show all notes
    conn = get_db_connection()
    notes = conn.execute("SELECT * FROM notes ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('notes.html', notes=notes)

# Open Redirect
@app.route('/go')
def go():
    """Open redirect vulnerability"""
    url = request.args.get('url', '')
    if url:
        return redirect(url)
    return "No URL provided"

# SQL Injection vulnerabilities
@app.route('/product')
def product():
    """SQLi - error/boolean based"""
    product_id = request.args.get('id', '')
    
    try:
        conn = get_db_connection()
        # INTENTIONALLY VULNERABLE - string concatenation
        query = f"SELECT * FROM products WHERE id = {product_id}"
        products = conn.execute(query).fetchall()
        conn.close()
        
        return render_template('product.html', products=products)
    except sqlite3.Error as e:
        # Show raw error text
        return f"SQL Error: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """SQLi - login bypass"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        try:
            conn = get_db_connection()
            # INTENTIONALLY VULNERABLE - string concatenation
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            user = conn.execute(query).fetchone()
            conn.close()
            
            if user:
                session['user'] = username
                return redirect(url_for('index'))
            else:
                return "Login failed", 401
        except sqlite3.Error as e:
            return f"SQL Error: {str(e)}", 500
    
    return render_template('login.html')

@app.route('/api/search-json', methods=['POST'])
def api_search_json():
    """SQLi - JSON API endpoint"""
    try:
        data = request.get_json()
        q = data.get('q', '') if data else ''
        
        conn = get_db_connection()
        # INTENTIONALLY VULNERABLE - string concatenation
        query = f"SELECT name FROM products WHERE name LIKE '%{q}%'"
        products = conn.execute(query).fetchall()
        conn.close()
        
        return jsonify([product['name'] for product in products])
    except Exception as e:
        return f"Error: {str(e)}", 500

# CSRF - State change
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """CSRF vulnerability - no token protection"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        to_user = request.form.get('to_user', '')
        amount = float(request.form.get('amount', 0))
        
        try:
            conn = get_db_connection()
            # Deduct from current user
            conn.execute("UPDATE users SET balance = balance - ? WHERE username = ?", 
                        (amount, session['user']))
            # Add to target user
            conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", 
                        (amount, to_user))
            conn.commit()
            conn.close()
            
            return render_template('transfer_success.html', 
                                 from_user=session['user'], to_user=to_user, amount=amount)
        except Exception as e:
            return f"Transfer error: {str(e)}", 500
    
    return render_template('transfer.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
