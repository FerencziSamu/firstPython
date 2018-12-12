from functools import wraps
from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators, DateField
from passlib.hash import sha256_crypt
from subprocess import call
from _datetime import date
import os


hello = Flask(__name__)

# Config MySQL
hello.config['MYSQL_HOST'] = '192.168.0.102'
hello.config['MYSQL_USER'] = 'fin'
hello.config['MYSQL_PASSWORD'] = 'password'
hello.config['MYSQL_DB'] = 'myflaskapp'
hello.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MySQL
mysql = MySQL(hello)


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
    name = StringField('Name', [validators.Length(min=1, max=50)])
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
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute Query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

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
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            role = data['role']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                session['role'] = role

                flash('You are now logged in!', 'success')
                return redirect(url_for('home'))
            else:
                error = 'Invalid login'
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
    cur = mysql.connection.cursor()

    # Get Requests
    cur.execute("SELECT * FROM requests")

    allrequests = cur.fetchall()

    cur.execute("SELECT * FROM users WHERE role=0")

    registered = cur.fetchall()

    cur.execute("SELECT * FROM users WHERE role=1")

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

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO requests(start, finish, author) VALUES(%s, %s, %s)",
                    (start, finish, session['username']))

        cur.execute("UPDATE users SET requested_holidays=%s WHERE username=%s",
                    ([number_of_days], [session['username']]))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Request created', 'success')
        return redirect(url_for('add_request'))

    return render_template('add_request.html', form=form)


# Approve Registration
@hello.route('/approve_register/<string:id>', methods=['POST'])
@is_admin
def approve_register(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("UPDATE users SET role=1 WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Registration approved!', 'success')
    return redirect(url_for('dashboard'))


# Approve Request
@hello.route('/approve_request/<string:id>', methods=['POST'])
@is_admin
def approve_request(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("UPDATE requests SET state='approved' WHERE id=%s", [id])
    cur.execute("SELECT author FROM requests WHERE id=%s", [id])
    name = cur.fetchone()
    print(name)
    # cur.execute("UPDATE users SET requested_holidays=0 WHERE username=%s", [name])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Request approved!', 'success')
    return redirect(url_for('dashboard'))


# Postpone Request
@hello.route('/pending_request/<string:id>', methods=['POST'])
@is_admin
def pending_request(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("UPDATE requests SET state='pending' WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Request postponed!', 'success')
    return redirect(url_for('dashboard'))


# Reject Registration
@hello.route('/reject_register/<string:id>', methods=['POST'])
@is_admin
def reject_register(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM users WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('User rejected!', 'success')

    return redirect(url_for('dashboard'))


# Reject Request
@hello.route('/reject_request/<string:id>', methods=['POST'])
@is_admin
def reject_request(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM requests WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Request rejected!', 'success')

    return redirect(url_for('dashboard'))


# Promote to admin
@hello.route('/promote_user/<string:id>', methods=['POST'])
@is_admin
def promote_user(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("UPDATE users SET role=2 WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Promoted to admin!', 'success')

    return redirect(url_for('dashboard'))


# Demote to registered
@hello.route('/demote_user/<string:id>', methods=['POST'])
@is_admin
def demote_user(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("UPDATE users SET role=0 WHERE id=%s", [id])

    # Commit to DB
    mysql.connection.commit()

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
    port = int(os.environ.get('PORT', 5000))
    hello.run(debug=True, host='127.0.0.1', port=port)
