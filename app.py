from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from urllib.parse import quote_plus
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

password=quote_plus('@Umang2004')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{password}@localhost/grocery_list'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    items = Item.query.all()
    return render_template('index.html', items=items)


@app.route('/add', methods=['GET', 'POST'])
def add_item():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
            name = request.form['name']
            quantity = request.form['quantity']
            unit = request.form['unit']
        
            new_item = Item(name=name, quantity=int(quantity), unit=unit)
            db.session.add(new_item)
            db.session.commit()
        
            return redirect(url_for('index'))

    return render_template('add_item.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message=None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        repassword = request.form['repassword']
        password_hash = generate_password_hash(password) 

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            message='Username already exists!'
            return redirect(url_for('signup'))
        elif password != repassword:
            message='Passwords do not match!'
            return redirect(url_for('signup'))

        new_user = User(username=username, password=password_hash)
        db.session.add(new_user)
        db.session.commit()

        message='Account created successfully! You can now log in.'
        return redirect(url_for('login'))

    return render_template('signup.html',message=message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message=None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        # Check if the user exists and if the password matches
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Store user_id in session
            message='Login successful!', 'success'
            return redirect(url_for('index'))

        message='Invalid username or password!'
        return redirect(url_for('login'))

    return render_template('login.html',message=message)

@app.route('/logout')
def logout():
    session.pop('user_id', None) 
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)