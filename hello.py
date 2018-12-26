import sqlite3
from functools import wraps
from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, validators, DateField
from passlib.hash import sha256_crypt
from subprocess import call
from _datetime import date, datetime


hello = Flask(__name__)

hello.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flask_db.db'
hello.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(hello)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    role = db.Column(db.Integer, nullable=False, default=0)
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    base_holidays = db.Column(db.Integer, nullable=False, default=25)
    requested_holidays = db.Column(db.String(45), nullable=False, default=0)
    remaining_holidays = db.Column(db.String(45), nullable=False, default=0)
    token = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80), unique=False, nullable=False)
    create_date = db.Column(db.DateTime, unique=False, nullable=False, default=datetime.utcnow())
    start = db.Column(db.DateTime, unique=False, nullable=False)
    finish = db.Column(db.DateTime, unique=False, nullable=False)
    state = db.Column(db.String(10), unique=False, nullable=False, default='Pending')

    def __repr__(self):
        return '<Request %r>' % self.id


db.drop_all()
db.create_all()
Admin = User(username='Samu', email='Samu77@freemail.hu', password='$5$rounds=535000$v8ENd9SnMU.Hk2TL$gJSQnSV6ctx6Y7zIFwZcOMolR8DhWh.MVhdwTGOU.X9', role=2)
db.session.add(Admin)
db.session.commit()


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please log in!', 'danger')
            return redirect(url_for('login'))

    return wrap


# Check if user registered
def is_registered_user(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('role') != 0:
            return f(*args, **kwargs)
        else:
            flash('You are not registered yet!', 'danger')
            return redirect(url_for('home'))

    return wrap


# Check if user is admin
def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('role') == 2:
            return f(*args, **kwargs)
        else:
            flash('You are not an administrator!', 'danger')
            return redirect(url_for('home'))

    return wrap


# Home page
@hello.route('/')
def home():
    return render_template('home.html')


# Registered Home page
@hello.route('/registered')
def registered():
    return render_template('registered.html')


# Employee page
@hello.route('/employee')
@is_registered_user
def employee():
    return render_template('employee.html')


# Employee page
@hello.route('/employee/calendarWidget.py')
@is_registered_user
def employee_widget():
    call(["python", "calendarWidget.py"])
    return render_template('employee.html')


# Register Form Class
class RegisterForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(),
                                          validators.EqualTo('confirm', message='Passwords do not match!')])
    confirm = PasswordField('Confirm Password')


# User Register
@hello.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('You are now registered and can log in!', 'success')

        return redirect(url_for('home'))
    return render_template('register.html', form=form)


# User login
@hello.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        conn = sqlite3.connect('flask_db.db')
        cur = conn.cursor()

        # Get user by username
        cur.execute("SELECT * FROM user WHERE username = ?", [username])
        res = cur.fetchone()

        if res is not None:
            # Get stored hash
            password = res[3]
            role = res[4]

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                session['role'] = role

                flash('You are now logged in!', 'success')
                return redirect(url_for('home'))
            else:
                error = 'Invalid password!'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found!'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Admin page with dashboard html
@hello.route('/admin')
@is_admin
def dashboard():
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Get Requests
    cur.execute("SELECT * FROM request")

    allrequests = cur.fetchall()

    cur.execute("SELECT * FROM user WHERE role=0")

    registered = cur.fetchall()

    cur.execute("SELECT * FROM user WHERE role=1")

    employees = cur.fetchall()

    return render_template('dashboard.html', allrequests=allrequests, registered=registered, employees=employees)

    # Close connection
    cur.close()


# Request Form Class
class RequestForm(Form):
    start = DateField('Start day of the leave', format='%Y-%m-%d')
    finish = DateField('Last day of the leave', format='%Y-%m-%d')


# Add Request
@hello.route('/add_request', methods=['GET', 'POST'])
@is_registered_user
def add_request():
    form = RequestForm(request.form)

    if request.method == 'POST' and form.validate():
        start = form.start.data
        finish = form.finish.data
        date_1 = date(start.year, start.month, start.day)
        date_2 = date(finish.year, finish.month, finish.day)
        number_of_days = (date_2 - date_1).days

        req = Request(author=session['username'], start=start, finish=finish)
        db.session.add(req)
        db.session.commit()

        flash('Request created', 'success')
        return redirect(url_for('add_request'))

    return render_template('add_request.html', form=form)


# Approve Registration
@hello.route('/approve_register/<string:id>', methods=['POST'])
@is_admin
def approve_register(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("UPDATE user SET role=1 WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('Registration approved!', 'success')
    return redirect(url_for('dashboard'))


# Approve Request
@hello.route('/approve_request/<string:id>', methods=['POST'])
@is_admin
def approve_request(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("UPDATE request SET state='approved' WHERE id=?", [id])
    cur.execute("SELECT author FROM request WHERE id=?", [id])

    # cur.execute("UPDATE users SET requested_holidays=0 WHERE username=%s", [name])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('Request approved!', 'success')
    return redirect(url_for('dashboard'))


# Postpone Request
@hello.route('/pending_request/<string:id>', methods=['POST'])
@is_admin
def pending_request(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("UPDATE request SET state='pending' WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('Request postponed!', 'success')
    return redirect(url_for('dashboard'))


# Reject Registration
@hello.route('/reject_register/<string:id>', methods=['POST'])
@is_admin
def reject_register(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("DELETE FROM user WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('User rejected!', 'success')

    return redirect(url_for('dashboard'))


# Reject Request
@hello.route('/reject_request/<string:id>', methods=['POST'])
@is_admin
def reject_request(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("DELETE FROM request WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('Request rejected!', 'success')

    return redirect(url_for('dashboard'))


# Promote to admin
@hello.route('/promote_user/<string:id>', methods=['POST'])
@is_admin
def promote_user(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("UPDATE user SET role=2 WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('Promoted to admin!', 'success')

    return redirect(url_for('dashboard'))


# Demote to registered
@hello.route('/demote_user/<string:id>', methods=['POST'])
@is_admin
def demote_user(id):
    # Create cursor
    conn = sqlite3.connect('flask_db.db')
    cur = conn.cursor()

    # Execute
    cur.execute("UPDATE user SET role=0 WHERE id=?", [id])

    # Commit to DB
    conn.commit()

    # Close connection
    cur.close()

    flash('And the employee finds him/herself again in a position of someone whose application needs to be '
          'approved, nice job!', 'success')

    return redirect(url_for('dashboard'))


# Logout
@hello.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out!', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    hello.secret_key = b'jz\x8dB\xf3\xeb\n\xe3\x9f\x9c\xf7\x8e\xc3"\x8d\x13\xf2\xb9\xd8QxQ6\xcf'
    hello.run(debug=True)
