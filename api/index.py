import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import func
import jwt

app = Flask(__name__)
CORS(app, resources={r'/*': {'origins': '*'}}, allow_headers=['Content-Type','Authorization'], methods=['GET','POST','PUT','DELETE','OPTIONS'])

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/tmp/spendwise.db' if os.path.exists('/tmp') else os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'spendwise.db'))

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'spendwise_secret_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Expense(db.Model):
    __tablename__ = 'expense'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Budget(db.Model):
    __tablename__ = 'budget'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    limit = db.Column(db.Float, nullable=False)
    month = db.Column(db.String(7), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    print('Database ready at: ' + DB_PATH)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split(' ')
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(user_id, *args, **kwargs)
    return decorator

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'SpendWise API running!', 'db': DB_PATH})

@app.route('/auth/signup', methods=['POST','OPTIONS'])
def signup():
    if request.method == 'OPTIONS': return jsonify({}), 200
    try:
        data = request.get_json(force=True) or {}
        username = data.get('username','').strip()
        password = data.get('password','')
        email = data.get('email','').strip()
        if not username or len(username) < 3:
            return jsonify({'message': 'Username must be at least 3 characters.'}), 400
        if not password or len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters.'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already taken.'}), 409
        db.session.add(User(username=username, email=email or None, password=generate_password_hash(password)))
        db.session.commit()
        return jsonify({'message': 'Account created successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/auth/login', methods=['POST','OPTIONS'])
def login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    try:
        data = request.get_json(force=True) or {}
        username = data.get('username','').strip()
        password = data.get('password','')
        if not username or not password:
            return jsonify({'message': 'Username and password required.'}), 400
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid username or password.'}), 401
        token = jwt.encode({'id': user.id, 'username': user.username, 'exp': datetime.utcnow() + timedelta(hours=8)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token, 'user_id': user.id, 'username': user.username})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/expenses/add', methods=['POST','OPTIONS'])
@token_required
def add_expense(user_id):
    if request.method == 'OPTIONS': return jsonify({}), 200
    try:
        data = request.get_json(force=True) or {}
        if not data.get('category') or not data.get('amount') or not data.get('date'):
            return jsonify({'message': 'Category, amount and date required.'}), 400
        e = Expense(user_id=user_id, category=data['category'], amount=float(data['amount']), description=data.get('description',''), date=datetime.strptime(data['date'],'%Y-%m-%d').date())
        db.session.add(e)
        db.session.commit()
        return jsonify({'message': 'Expense added!', 'id': e.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/expenses/list', methods=['GET'])
@token_required
def list_expenses(user_id):
    try:
        month = request.args.get('month')
        q = Expense.query.filter_by(user_id=user_id)
        if month:
            yr, mn = month.split('-')
            q = q.filter(func.strftime('%Y', Expense.date)==yr, func.strftime('%m', Expense.date)==mn.zfill(2))
        return jsonify([{'id':e.id,'category':e.category,'amount':e.amount,'description':e.description,'date':e.date.strftime('%Y-%m-%d')} for e in q.order_by(Expense.date.desc()).all()])
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/expenses/delete/<int:eid>', methods=['DELETE'])
@token_required
def delete_expense(user_id, eid):
    try:
        e = Expense.query.filter_by(id=eid, user_id=user_id).first()
        if not e: return jsonify({'message': 'Not found.'}), 404
        db.session.delete(e)
        db.session.commit()
        return jsonify({'message': 'Deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/expenses/summary', methods=['GET'])
@token_required
def summary(user_id):
    try:
        month = request.args.get('month')
        q = Expense.query.filter_by(user_id=user_id)
        if month:
            yr, mn = month.split('-')
            q = q.filter(func.strftime('%Y', Expense.date)==yr, func.strftime('%m', Expense.date)==mn.zfill(2))
        expenses = q.all()
        by_cat = {}
        for e in expenses:
            by_cat[e.category] = by_cat.get(e.category, 0) + e.amount
        return jsonify({'total': round(sum(e.amount for e in expenses), 2), 'by_category': {k: round(v,2) for k,v in by_cat.items()}, 'count': len(expenses)})
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/budgets/set', methods=['POST','OPTIONS'])
@token_required
def set_budget(user_id):
    if request.method == 'OPTIONS': return jsonify({}), 200
    try:
        data = request.get_json(force=True) or {}
        if not data.get('category') or not data.get('limit') or not data.get('month'):
            return jsonify({'message': 'Category, limit and month required.'}), 400
        existing = Budget.query.filter_by(user_id=user_id, category=data['category'], month=data['month']).first()
        if existing:
            existing.limit = float(data['limit'])
            db.session.commit()
            return jsonify({'message': 'Budget updated!', 'id': existing.id})
        b = Budget(user_id=user_id, category=data['category'], limit=float(data['limit']), month=data['month'])
        db.session.add(b)
        db.session.commit()
        return jsonify({'message': 'Budget set!', 'id': b.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/budgets/list', methods=['GET'])
@token_required
def list_budgets(user_id):
    try:
        month = request.args.get('month')
        q = Budget.query.filter_by(user_id=user_id)
        if month: q = q.filter_by(month=month)
        result = []
        for b in q.all():
            yr, mn = b.month.split('-')
            spent = db.session.query(func.sum(Expense.amount)).filter(Expense.user_id==user_id, Expense.category==b.category, func.strftime('%Y',Expense.date)==yr, func.strftime('%m',Expense.date)==mn.zfill(2)).scalar() or 0
            result.append({'id':b.id,'category':b.category,'limit':b.limit,'spent':round(spent,2),'remaining':round(b.limit-spent,2),'percent':round((spent/b.limit)*100,1) if b.limit>0 else 0,'month':b.month})
        return jsonify(result)
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/budgets/delete/<int:bid>', methods=['DELETE'])
@token_required
def delete_budget(user_id, bid):
    try:
        b = Budget.query.filter_by(id=bid, user_id=user_id).first()
        if not b: return jsonify({'message': 'Not found.'}), 404
        db.session.delete(b)
        db.session.commit()
        return jsonify({'message': 'Deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)


