from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import func
import jwt
import os

# ── App Setup ──────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Use /tmp for SQLite on Vercel (writable directory)
DB_PATH = "/tmp/spendwise.db"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'spendwise_vercel_secret_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ── Models ─────────────────────────────────────────────────
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    limit = db.Column(db.Float, nullable=False)
    month = db.Column(db.String(7), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# ── Auth Middleware ─────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split(" ")
            if len(parts) == 2 and parts[0] == "Bearer":
                token = parts[1]
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data['id']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except Exception:
            return jsonify({"message": "Token is invalid!"}), 401
        return f(user_id, *args, **kwargs)
    return decorator

# ── Validators ─────────────────────────────────────────────
def validate_signup(data):
    if not data.get('username') or len(data['username'].strip()) < 3:
        return "Username must be at least 3 characters."
    if not data.get('password') or len(data['password']) < 6:
        return "Password must be at least 6 characters."
    return None

# ── Auth Routes ────────────────────────────────────────────
@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json or {}
    err = validate_signup(data)
    if err:
        return jsonify({"message": err}), 400
    if User.query.filter_by(username=data['username'].strip()).first():
        return jsonify({"message": "Username already taken."}), 409
    new_user = User(
        username=data['username'].strip(),
        email=data.get('email', '').strip() or None,
        password=generate_password_hash(data['password'])
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Account created successfully!"}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    if not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password required."}), 400
    user = User.query.filter_by(username=data['username'].strip()).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid username or password."}), 401
    token = jwt.encode(
        {'id': user.id, 'username': user.username,
         'exp': datetime.utcnow() + timedelta(hours=8)},
        app.config['SECRET_KEY'], algorithm="HS256"
    )
    return jsonify({"token": token, "user_id": user.id, "username": user.username})

@app.route('/auth/me', methods=['GET'])
@token_required
def me(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"id": user.id, "username": user.username, "email": user.email})

# ── Expense Routes ─────────────────────────────────────────
@app.route('/expenses/add', methods=['POST'])
@token_required
def add_expense(user_id):
    data = request.json or {}
    if not data.get('category') or not data.get('amount') or not data.get('date'):
        return jsonify({"message": "Category, amount and date are required."}), 400
    expense = Expense(
        user_id=user_id,
        category=data['category'],
        amount=float(data['amount']),
        description=data.get('description', ''),
        date=datetime.strptime(data['date'], '%Y-%m-%d').date()
    )
    db.session.add(expense)
    db.session.commit()
    return jsonify({"message": "Expense added!", "id": expense.id}), 201

@app.route('/expenses/list', methods=['GET'])
@token_required
def list_expenses(user_id):
    month = request.args.get('month')
    query = Expense.query.filter_by(user_id=user_id)
    if month:
        year, mon = month.split('-')
        query = query.filter(
            func.strftime('%Y', Expense.date) == year,
            func.strftime('%m', Expense.date) == mon.zfill(2)
        )
    expenses = query.order_by(Expense.date.desc()).all()
    return jsonify([{
        "id": e.id, "category": e.category, "amount": e.amount,
        "description": e.description, "date": e.date.strftime('%Y-%m-%d')
    } for e in expenses])

@app.route('/expenses/delete/<int:expense_id>', methods=['DELETE'])
@token_required
def delete_expense(user_id, expense_id):
    expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()
    if not expense:
        return jsonify({"message": "Expense not found."}), 404
    db.session.delete(expense)
    db.session.commit()
    return jsonify({"message": "Expense deleted."})

@app.route('/expenses/summary', methods=['GET'])
@token_required
def summary(user_id):
    month = request.args.get('month')
    query = Expense.query.filter_by(user_id=user_id)
    if month:
        year, mon = month.split('-')
        query = query.filter(
            func.strftime('%Y', Expense.date) == year,
            func.strftime('%m', Expense.date) == mon.zfill(2)
        )
    expenses = query.all()
    total = sum(e.amount for e in expenses)
    by_cat = {}
    for e in expenses:
        by_cat[e.category] = by_cat.get(e.category, 0) + e.amount
    return jsonify({
        "total": round(total, 2),
        "by_category": {k: round(v, 2) for k, v in by_cat.items()},
        "count": len(expenses)
    })

# ── Budget Routes ──────────────────────────────────────────
@app.route('/budgets/set', methods=['POST'])
@token_required
def set_budget(user_id):
    data = request.json or {}
    if not data.get('category') or not data.get('limit') or not data.get('month'):
        return jsonify({"message": "Category, limit and month are required."}), 400
    existing = Budget.query.filter_by(
        user_id=user_id, category=data['category'], month=data['month']
    ).first()
    if existing:
        existing.limit = float(data['limit'])
        db.session.commit()
        return jsonify({"message": "Budget updated!", "id": existing.id})
    budget = Budget(
        user_id=user_id, category=data['category'],
        limit=float(data['limit']), month=data['month']
    )
    db.session.add(budget)
    db.session.commit()
    return jsonify({"message": "Budget set!", "id": budget.id}), 201

@app.route('/budgets/list', methods=['GET'])
@token_required
def list_budgets(user_id):
    month = request.args.get('month')
    query = Budget.query.filter_by(user_id=user_id)
    if month:
        query = query.filter_by(month=month)
    budgets = query.all()
    result = []
    for b in budgets:
        year, mon = b.month.split('-')
        spent = db.session.query(func.sum(Expense.amount)).filter(
            Expense.user_id == user_id,
            Expense.category == b.category,
            func.strftime('%Y', Expense.date) == year,
            func.strftime('%m', Expense.date) == mon.zfill(2)
        ).scalar() or 0
        result.append({
            "id": b.id, "category": b.category,
            "limit": b.limit, "spent": round(spent, 2),
            "remaining": round(b.limit - spent, 2),
            "percent": round((spent / b.limit) * 100, 1) if b.limit > 0 else 0,
            "month": b.month
        })
    return jsonify(result)

@app.route('/budgets/delete/<int:budget_id>', methods=['DELETE'])
@token_required
def delete_budget(user_id, budget_id):
    budget = Budget.query.filter_by(id=budget_id, user_id=user_id).first()
    if not budget:
        return jsonify({"message": "Budget not found."}), 404
    db.session.delete(budget)
    db.session.commit()
    return jsonify({"message": "Budget deleted."})

# ── Health Check ───────────────────────────────────────────
@app.route('/', methods=['GET'])
def health():
    return jsonify({"status": "SpendWise API running!", "version": "2.0"})

# Vercel needs the app object
if __name__ == "__main__":
    app.run(debug=True)
