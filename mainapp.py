import os

import bcrypt

from flask import *


def write_user_data(username, password, email):
    with open('users.txt', 'a') as f:
        f.write(f'{username},{password},{email}\n')

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        signup_user = None
        with open('users.txt', 'r') as f:
            for line in f:
                user_data = line.strip().split(',')
                if user_data[0] == request.form['username']:
                    signup_user = user_data[0]
                    break

        if signup_user:
            flash(request.form['username'] + ' username is already exist')
            return redirect(url_for('signup'))

        hashed = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt(14))
        write_user_data(request.form['username'], hashed, request.form['email'])
        return redirect(url_for('signin'))

    return render_template('signup.html')

def read_user_data(username):
    with open('users.txt', 'r') as f:
        for line in f:
            user_data = line.strip().split(',')
            if user_data[0] == username:
                return user_data
    return None

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        signin_user = read_user_data(request.form['username'])

        if signin_user:
            if bcrypt.hashpw(request.form['password'].encode('utf-8'), signin_user[1].encode('utf-8')) == \
                    signin_user[1].encode('utf-8'):
                session['username'] = request.form['username']
                return redirect(url_for('index'))

        flash('Username and password combination is wrong')
        return render_template('signin.html')

    return render_template('signin.html')