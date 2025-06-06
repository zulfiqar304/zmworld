from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # Change to something strong
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------------- DATABASE MODELS ---------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    coins = db.Column(db.Integer, default=10)
    last_login_date = db.Column(db.String(20))  # YYYY-MM-DD format

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service = db.Column(db.String(100))
    link = db.Column(db.String(300))
    quantity = db.Column(db.Integer)
    coins_required = db.Column(db.Integer)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------- SERVICES & COIN RATES ---------------------- #
SERVICES = {
    'instagram_followers': 1,
    'instagram_likes': 1,
    'youtube_views': 2,
    'youtube_subscribers': 3,
    'facebook_likes': 1,
    'facebook_followers': 2,
    'tiktok_followers': 2,
    'tiktok_likes': 1,
    'twitter_followers': 2,
    'twitter_likes': 1
}

# ---------------------- ROUTES ---------------------- #
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash('Please fill in all fields.')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            today = datetime.now().strftime("%Y-%m-%d")
            if user.last_login_date != today:
                user.coins += 5  # daily login bonus
                user.last_login_date = today
                db.session.commit()

            session['user_id'] = user.id
            flash(f'Welcome back, {user.username}!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access dashboard.')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/place-order', methods=['GET', 'POST'])
def place_order():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        service = request.form.get('service')
        link = request.form.get('link').strip()
        quantity_str = request.form.get('quantity')

        # Validate inputs
        if not service or not link or not quantity_str:
            flash('Please fill all fields.')
            return redirect(url_for('place_order'))

        try:
            quantity = int(quantity_str)
            if quantity <= 0:
                flash('Quantity must be a positive number.')
                return redirect(url_for('place_order'))
        except ValueError:
            flash('Quantity must be a number.')
            return redirect(url_for('place_order'))

        if service not in SERVICES:
            flash('Invalid service selected.')
            return redirect(url_for('place_order'))

        cost = quantity * SERVICES[service]
        if user.coins < cost:
            flash('Insufficient coins to place this order.')
            return redirect(url_for('place_order'))

        # Place order and deduct coins
        new_order = Order(
            user_id=user.id,
            service=service,
            link=link,
            quantity=quantity,
            coins_required=cost,
            status='Pending'
        )
        user.coins -= cost
        db.session.add(new_order)
        db.session.commit()

        flash('Order placed successfully!')
        return redirect(url_for('order_history'))

    return render_template('place_order.html', user=user, services=SERVICES)

@app.route('/order-history')
def order_history():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    return render_template('order_history.html', user=user, orders=orders)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
