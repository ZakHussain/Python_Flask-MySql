from flask import Flask, redirect, request, render_template, session, flash  

from mysqlconnection import MySQLConnector
import re
from flask.ext.bcrypt import Bcrypt
app = Flask(__name__)	
bcrypt = Bcrypt(app)	
mysql = MySQLConnector(app, 'login_info')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app.secret_key = "ThisIsSecret!"

@app.route('/')
def homescreen():
	return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
	email = request.form['user_email']
	password = request.form['user_password']
	user_query = "SELECT * FROM info WHERE email = :email LIMIT 1"
	query_data = { 'email': email }
	user = mysql.query_db(user_query, query_data)
	if bcrypt.check_password_hash(user[0]['pw_hash'], password):
		flash("Login Successful!", 'Login')
	else:
		flash("Login Failed!" 'Login')
	return redirect('/')

@app.route('/process', methods=['POST'])
def submit():
	session['first_name'] = request.form['first_name']
	session['last_name'] = request.form['last_name']
	session['email'] = request.form['email']
	session['password'] = request.form['password']
	session['confirmation'] = request.form['confirmation']
	pw_hash = bcrypt.generate_password_hash(session['password'])

	if len(session['first_name'])<2:
		flash("first name must contain at least two characters...", Register)

	elif (session['first_name']).isalpha() == False:
		flash("name can only contain alphabetical characters...", Register)

	elif len(session['last_name'])<2:
		flash("last name must contain at least two characters...", Register)

	elif session['last_name'].isalpha() == False:
		flash("name can only contain alphabetical characters...", Register)

	elif len(session['email'])<1:
		flash("Email cannot be left blank...", Register)

	elif not EMAIL_REGEX.match(request.form['email']):
		flash("Invalid Email Address...", Register)

	elif len(session['password'])<8:
		flash("Password must have at leat 8 characters...", Register)

	elif session['password'] != session['confirmation']:
		flash("Passwords do not match...", Register)

	else:
		flash("Registration Information Added!")
		query = "INSERT INTO info (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES(:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
		data = {
					'first_name': session['first_name'],
					'last_name': session['last_name'],
					'email': session['email'],
					'pw_hash': pw_hash
				}	
		mysql.query_db(query, data)
	return redirect('/')
app.run(debug=True)
