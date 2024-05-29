from flask import Flask, render_template, url_for, request, session, redirect, flash
from tinydb import TinyDB, Query
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
db = TinyDB('users.json')
query = Query()

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        existing_user = db.search(query.username == request.form['username'])

        if existing_user:
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('signup'))

        hashed = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt(14))
        db.insert({'username': request.form['username'], 'password': hashed.decode('utf-8')})
        session['username'] = request.form['username']
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        signin_user = db.search(query.username == request.form['username'])

        if signin_user and bcrypt.checkpw(request.form['password'].encode('utf-8'), signin_user[0]['password'].encode('utf-8')):
            session['username'] = request.form['username']
            return redirect(url_for('index'))

        flash('Username and password combination is wrong')
        return render_template('signin.html')

    return render_template('signin.html')

@app.route('/index')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    else:
        return redirect(url_for('signin'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)