#!/usr/bin/env python3
"""
Financial Planner Pro - Backend API
Flask server with SQLite database, user authentication, and transaction tracking
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
import datetime
from functools import wraps
import os
import json
import csv
from io import StringIO

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# Secret key for JWT (change this in production!)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

# Database initialization
def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Budgets table
    c.execute('''CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        month TEXT NOT NULL,
        income REAL NOT NULL,
        total_expenses REAL NOT NULL,
        remaining REAL NOT NULL,
        health_score INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Expenses table
    c.execute('''CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        budget_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        FOREIGN KEY (budget_id) REFERENCES budgets (id)
    )''')
    
    # Transactions table
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        date TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        severity TEXT NOT NULL,
        is_read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    # Goals table
    c.execute('''CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        target_amount REAL NOT NULL,
        current_amount REAL DEFAULT 0,
        deadline TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

# ===== AUTHENTICATION ROUTES =====

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    # Check if user exists
    c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    if c.fetchone():
        conn.close()
        return jsonify({'message': 'User already exists'}), 409
    
    # Create user
    password_hash = generate_password_hash(password)
    c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
              (username, email, password_hash))
    conn.commit()
    user_id = c.lastrowid
    conn.close()
    
    # Generate token
    token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': 'Registration successful',
        'token': token,
        'user': {'id': user_id, 'username': username, 'email': email}
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Missing credentials'}), 400
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    c.execute('SELECT id, username, email, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or not check_password_hash(user[3], password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate token
    token = jwt.encode({
        'user_id': user[0],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {'id': user[0], 'username': user[1], 'email': user[2]}
    }), 200

# ===== BUDGET ROUTES =====

@app.route('/api/budgets', methods=['POST'])
@token_required
def create_budget(current_user_id):
    """Create a new budget"""
    data = request.get_json()
    
    month = data.get('month', datetime.datetime.now().strftime('%Y-%m'))
    income = data.get('income')
    expenses = data.get('expenses', {})
    
    if not income:
        return jsonify({'message': 'Income is required'}), 400
    
    total_expenses = sum(expenses.values())
    remaining = income - total_expenses
    
    # Calculate health score
    health_score = calculate_health_score(income, total_expenses, remaining, expenses)
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    # Create budget
    c.execute('''INSERT INTO budgets (user_id, month, income, total_expenses, remaining, health_score)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (current_user_id, month, income, total_expenses, remaining, health_score))
    budget_id = c.lastrowid
    
    # Save expenses
    for category, amount in expenses.items():
        c.execute('INSERT INTO expenses (budget_id, category, amount) VALUES (?, ?, ?)',
                  (budget_id, category, amount))
    
    # Generate alerts
    generate_alerts(current_user_id, income, total_expenses, remaining, expenses, c)
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': 'Budget created successfully',
        'budget_id': budget_id,
        'health_score': health_score
    }), 201

@app.route('/api/budgets', methods=['GET'])
@token_required
def get_budgets(current_user_id):
    """Get all budgets for current user"""
    conn = sqlite3.connect('financial_planner.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''SELECT * FROM budgets WHERE user_id = ? ORDER BY created_at DESC''',
              (current_user_id,))
    budgets = [dict(row) for row in c.fetchall()]
    
    # Get expenses for each budget
    for budget in budgets:
        c.execute('SELECT category, amount FROM expenses WHERE budget_id = ?', (budget['id'],))
        budget['expenses'] = {row[0]: row[1] for row in c.fetchall()}
    
    conn.close()
    
    return jsonify(budgets), 200

@app.route('/api/budgets/latest', methods=['GET'])
@token_required
def get_latest_budget(current_user_id):
    """Get the most recent budget"""
    conn = sqlite3.connect('financial_planner.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''SELECT * FROM budgets WHERE user_id = ? ORDER BY created_at DESC LIMIT 1''',
              (current_user_id,))
    budget = c.fetchone()
    
    if not budget:
        conn.close()
        return jsonify({'message': 'No budgets found'}), 404
    
    budget = dict(budget)
    
    # Get expenses
    c.execute('SELECT category, amount FROM expenses WHERE budget_id = ?', (budget['id'],))
    budget['expenses'] = {row[0]: row[1] for row in c.fetchall()}
    
    conn.close()
    
    return jsonify(budget), 200

# ===== TRANSACTION ROUTES =====

@app.route('/api/transactions', methods=['POST'])
@token_required
def create_transaction(current_user_id):
    """Add a new transaction"""
    data = request.get_json()
    
    trans_type = data.get('type')  # 'income' or 'expense'
    category = data.get('category')
    amount = data.get('amount')
    description = data.get('description', '')
    date = data.get('date', datetime.datetime.now().strftime('%Y-%m-%d'))
    
    if not all([trans_type, category, amount]):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO transactions (user_id, type, category, amount, description, date)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (current_user_id, trans_type, category, amount, description, date))
    
    transaction_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': 'Transaction added successfully',
        'transaction_id': transaction_id
    }), 201

@app.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user_id):
    """Get all transactions for current user"""
    # Optional filters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    trans_type = request.args.get('type')
    category = request.args.get('category')
    
    conn = sqlite3.connect('financial_planner.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    query = 'SELECT * FROM transactions WHERE user_id = ?'
    params = [current_user_id]
    
    if start_date:
        query += ' AND date >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND date <= ?'
        params.append(end_date)
    if trans_type:
        query += ' AND type = ?'
        params.append(trans_type)
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    query += ' ORDER BY date DESC, created_at DESC'
    
    c.execute(query, params)
    transactions = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return jsonify(transactions), 200

@app.route('/api/transactions/<int:transaction_id>', methods=['DELETE'])
@token_required
def delete_transaction(current_user_id, transaction_id):
    """Delete a transaction"""
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    c.execute('DELETE FROM transactions WHERE id = ? AND user_id = ?',
              (transaction_id, current_user_id))
    
    if c.rowcount == 0:
        conn.close()
        return jsonify({'message': 'Transaction not found'}), 404
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Transaction deleted successfully'}), 200

# ===== ALERTS ROUTES =====

@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user_id):
    """Get all alerts for current user"""
    conn = sqlite3.connect('financial_planner.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute('''SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 50''',
              (current_user_id,))
    alerts = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return jsonify(alerts), 200

@app.route('/api/alerts/<int:alert_id>/read', methods=['PUT'])
@token_required
def mark_alert_read(current_user_id, alert_id):
    """Mark an alert as read"""
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    c.execute('UPDATE alerts SET is_read = 1 WHERE id = ? AND user_id = ?',
              (alert_id, current_user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Alert marked as read'}), 200

# ===== ANALYTICS ROUTES =====

@app.route('/api/analytics/spending-by-category', methods=['GET'])
@token_required
def spending_by_category(current_user_id):
    """Get spending breakdown by category"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    query = '''SELECT category, SUM(amount) as total 
               FROM transactions 
               WHERE user_id = ? AND type = 'expense' '''
    params = [current_user_id]
    
    if start_date:
        query += ' AND date >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND date <= ?'
        params.append(end_date)
    
    query += ' GROUP BY category ORDER BY total DESC'
    
    c.execute(query, params)
    results = [{'category': row[0], 'total': row[1]} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify(results), 200

@app.route('/api/analytics/trends', methods=['GET'])
@token_required
def get_trends(current_user_id):
    """Get spending trends over time"""
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    # Monthly spending
    c.execute('''SELECT strftime('%Y-%m', date) as month, 
                        SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
                        SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expenses
                 FROM transactions 
                 WHERE user_id = ?
                 GROUP BY month
                 ORDER BY month DESC
                 LIMIT 12''', (current_user_id,))
    
    trends = [{'month': row[0], 'income': row[1], 'expenses': row[2]} 
              for row in c.fetchall()]
    
    conn.close()
    
    return jsonify(trends), 200

@app.route('/api/analytics/behavioral-insights', methods=['GET'])
@token_required
def behavioral_insights(current_user_id):
    """Generate behavioral insights based on spending patterns"""
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    insights = []
    
    # 1. Top spending category
    c.execute('''SELECT category, SUM(amount) as total 
                 FROM transactions 
                 WHERE user_id = ? AND type = 'expense'
                 AND date >= date('now', '-30 days')
                 GROUP BY category 
                 ORDER BY total DESC 
                 LIMIT 1''', (current_user_id,))
    top_category = c.fetchone()
    if top_category:
        insights.append({
            'type': 'top_spending',
            'message': f'Your biggest expense this month is {top_category[0]} (${top_category[1]:.2f})',
            'category': top_category[0],
            'amount': top_category[1]
        })
    
    # 2. Weekend vs weekday spending
    c.execute('''SELECT 
                    SUM(CASE WHEN CAST(strftime('%w', date) AS INTEGER) IN (0, 6) 
                        THEN amount ELSE 0 END) as weekend,
                    SUM(CASE WHEN CAST(strftime('%w', date) AS INTEGER) NOT IN (0, 6) 
                        THEN amount ELSE 0 END) as weekday
                 FROM transactions 
                 WHERE user_id = ? AND type = 'expense'
                 AND date >= date('now', '-30 days')''', (current_user_id,))
    spending_pattern = c.fetchone()
    if spending_pattern and spending_pattern[0] and spending_pattern[1]:
        if spending_pattern[0] > spending_pattern[1]:
            insights.append({
                'type': 'spending_pattern',
                'message': f'You spend more on weekends (${spending_pattern[0]:.2f}) vs weekdays (${spending_pattern[1]:.2f})',
                'weekend': spending_pattern[0],
                'weekday': spending_pattern[1]
            })
    
    # 3. Average daily spending
    c.execute('''SELECT AVG(daily_total) as avg_daily
                 FROM (
                     SELECT date, SUM(amount) as daily_total
                     FROM transactions
                     WHERE user_id = ? AND type = 'expense'
                     AND date >= date('now', '-30 days')
                     GROUP BY date
                 )''', (current_user_id,))
    avg_daily = c.fetchone()
    if avg_daily and avg_daily[0]:
        insights.append({
            'type': 'daily_average',
            'message': f'Your average daily spending is ${avg_daily[0]:.2f}',
            'amount': avg_daily[0]
        })
    
    # 4. Savings rate trend
    c.execute('''SELECT month, income, expenses, 
                        CASE WHEN income > 0 THEN ((income - expenses) / income * 100) ELSE 0 END as savings_rate
                 FROM (
                     SELECT strftime('%Y-%m', date) as month,
                            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
                            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expenses
                     FROM transactions
                     WHERE user_id = ?
                     GROUP BY month
                     ORDER BY month DESC
                     LIMIT 3
                 )''', (current_user_id,))
    months = c.fetchall()
    if len(months) >= 2:
        recent_rate = months[0][3]
        prev_rate = months[1][3]
        if recent_rate > prev_rate:
            insights.append({
                'type': 'savings_improvement',
                'message': f'Great job! Your savings rate improved from {prev_rate:.1f}% to {recent_rate:.1f}%',
                'current': recent_rate,
                'previous': prev_rate
            })
        elif recent_rate < prev_rate:
            insights.append({
                'type': 'savings_decline',
                'message': f'Your savings rate decreased from {prev_rate:.1f}% to {recent_rate:.1f}%. Consider reviewing expenses.',
                'current': recent_rate,
                'previous': prev_rate
            })
    
    conn.close()
    
    return jsonify(insights), 200

# ===== EXPORT ROUTES =====

@app.route('/api/export/transactions', methods=['GET'])
@token_required
def export_transactions(current_user_id):
    """Export transactions as CSV"""
    format_type = request.args.get('format', 'csv')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    conn = sqlite3.connect('financial_planner.db')
    c = conn.cursor()
    
    query = 'SELECT date, type, category, amount, description FROM transactions WHERE user_id = ?'
    params = [current_user_id]
    
    if start_date:
        query += ' AND date >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND date <= ?'
        params.append(end_date)
    
    query += ' ORDER BY date DESC'
    
    c.execute(query, params)
    transactions = c.fetchall()
    conn.close()
    
    if format_type == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Type', 'Category', 'Amount', 'Description'])
        writer.writerows(transactions)
        
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=transactions.csv'
        }
    else:
        # JSON format
        data = [
            {
                'date': row[0],
                'type': row[1],
                'category': row[2],
                'amount': row[3],
                'description': row[4]
            }
            for row in transactions
        ]
        return jsonify(data), 200

# ===== HELPER FUNCTIONS =====

def calculate_health_score(income, expenses, remaining, expense_breakdown):
    """Calculate financial health score"""
    score = 100
    
    if remaining < 0:
        score -= 40
    
    rent_ratio = expense_breakdown.get('Rent / Housing', 0) / income if income > 0 else 0
    if rent_ratio > 0.50:
        score -= 15
    elif rent_ratio > 0.30:
        score -= 5
    
    if remaining > 0:
        savings_rate = (remaining * 0.40) / income
        if savings_rate >= 0.20:
            score += 10
        elif savings_rate >= 0.10:
            score += 5
        elif savings_rate < 0.05:
            score -= 10
    
    remaining_ratio = remaining / income if income > 0 else 0
    if 0 <= remaining_ratio < 0.10:
        score -= 15
    
    return max(0, min(100, int(score)))

def generate_alerts(user_id, income, expenses, remaining, expense_breakdown, cursor):
    """Generate alerts based on budget analysis"""
    
    # Budget deficit alert
    if remaining < 0:
        cursor.execute('''INSERT INTO alerts (user_id, type, message, severity)
                         VALUES (?, ?, ?, ?)''',
                      (user_id, 'budget_deficit',
                       f'Your expenses exceed your income by ${abs(remaining):.2f}',
                       'danger'))
    
    # High rent alert
    rent_ratio = expense_breakdown.get('Rent / Housing', 0) / income if income > 0 else 0
    if rent_ratio > 0.50:
        cursor.execute('''INSERT INTO alerts (user_id, type, message, severity)
                         VALUES (?, ?, ?, ?)''',
                      (user_id, 'high_rent',
                       f'Housing costs are {rent_ratio*100:.1f}% of income (recommended: <30%)',
                       'warning'))
    
    # Low savings alert
    if remaining > 0:
        savings_rate = (remaining * 0.40) / income
        if savings_rate < 0.10:
            cursor.execute('''INSERT INTO alerts (user_id, type, message, severity)
                             VALUES (?, ?, ?, ?)''',
                          (user_id, 'low_savings',
                           f'Savings rate is {savings_rate*100:.1f}% (aim for 10-20%)',
                           'info'))

# ===== SERVE FRONTEND =====

@app.route('/')
def serve_frontend():
    """Serve the frontend HTML"""
    return send_from_directory(app.static_folder, 'index.html')

# ===== RUN SERVER =====

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("✅ Database initialized")
    print("🚀 Starting Financial Planner Pro API...")
    print("📍 Server running at http://localhost:5000")
    
    app.run(debug=True, port=5000)
