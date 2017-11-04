from models import Base, User, Category, Item, User_Profile, Google_Account, Facebook_Account
from flask import Flask, flash, make_response, render_template, redirect,request, jsonify, url_for, g, abort
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_httpauth import HTTPBasicAuth
from flask import session as login_session
import random, string
import httplib2
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import json
import requests
from flask_jwt import JWT, jwt_required
from security import authenticate, identity
auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
app.secret_key = "testing"
jwt = JWT(app, authenticate, identity)


CLIENT_ID = json.loads(open('client_secret_google.json', 'r').read())['web']['client_id']

@app.route('/login', methods=['GET', 'POST'])
def login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('pwd')
		if(userLogin(email, password)): 
			return redirect(url_for('catalogHandler'))
		else:
			return redirect(url_for('login'))
	else: 
		return render_template('login.html', STATE=state)

def verify_password(username_or_token, password):
	pass

def userLogin(email, password):
	if email is None or email == "" or password is None or password == "":
		flash("Email for password fields are empty")
		return False
	user = session.query(User).filter_by(email=email).first()
	if not user or not user.verify_password(password):
		flash("We wern't able to find the email address and password combination you entered")
		return False;

	login_session['email'] = email
	login_session['username'] = user.username
	login_session['picture'] = user.picture
	return True

@app.route('/fbconnect', methods=['GET', 'POST'])
def fbconnect():
	#validate state token
	if request.args.get('state') != login_session['state']:
                response = make_response(json.dumps('Invalid state token'), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
	
	access_token = request.data
	#exchange a long live token
	app_id = json.loads(open('fb_client_secret.json', 'r').read())['web']['app_id']
        app_secret = json.loads(open('fb_client_secret.json', 'r').read())['web']['app_secret']
        url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' %(app_id, app_secret, access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        userinfor_url = "https://graph.facebook.com/v2.8/me"
        token = result.split(',')[0].split(":")[1].replace('"','')

        url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' %token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)
        login_session['username'] = data['name']
        login_session['email'] = data['email']
        login_session['facebook_id'] = data['id']
        login_session['provider'] = 'facebook'
        login_session['access_token'] = token
	login_session['firstname'] = data['name']
	login_session['lastname'] = data['name']


	#get user picture
        url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
        h = httplib2.Http()
        result = h.request(url, 'GET')[1]
        data = json.loads(result)
        login_session['picture'] = data["data"]["url"]

        #check if user exist
        uid = getUserID(login_session['email'])
        if not uid:
                uid = createUserFromFacebook(login_session)
        login_session['user_id'] = uid


        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        #output += login_session['picture']
        #output += ' " style = "width: 150px; height: 150px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        flash("you are now logged in as %s" % login_session['username'])
        return output



@app.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
	#validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state token'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#obtain one time authorization code
	code = request.data
	try:
		#upgrade the authorization code into a credential object
		oauth_flow = flow_from_clientsecrets('client_secret_google.json', scope='profile', redirect_uri='postmessage')
		credentials = oauth_flow.step2_exchange(code)
			
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to ugrade the authorization code.'), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
	access_token = credentials.access_token
	#check tha access token is valid to avoid confused deputy problem vulnerability
	url = ('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s'% access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])

	#if there was an error in the access token
        if(result.get('error') is not None):
                response = make_response(json.dumps(result.get('error')), 500)
                response.headers['Content-Type'] = 'application/json'
                return response

	#verify the access token is used for the intended user
        gplus_id = credentials.id_token['sub']
	if result['sub'] != gplus_id:
		response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
	

	# verify the access token is valid for this app
	if result['aud'] != CLIENT_ID:
		response = make_response(json.dumps("Token's client ID does not match app's."), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
	stored_access_token = login_session.get('access_token')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_access_token is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'),200)
                response.headers['Content-Type'] = 'application/json'
                return response
	#store the accress token in the session for later use
        login_session['access_token'] = credentials.access_token
        #login_session['gplus_id'] = gplus_id
	
	#get user info
	userinfo_url = "https://www.googleapis.com/plus/v1/people/me"
	params={'access_token': credentials.access_token, 'alt':'json'}
	answer = requests.get('https://www.googleapis.com/plus/v1/people/me', params=params)
	data = answer.json()

	login_session['username'] = data['displayName']
	login_session['picture'] = data['image']['url']
	login_session['email'] = data['emails'][0]['value']
	login_session['provider'] = 'google'
	login_session['google_id'] = data['id']
	login_session['firstname'] = data['name'].get('givenName')
	login_session['lastname'] = data['name'].get('familyName')	
	#see if user exist in the database, if not, then make a new one
	uid = getUserID(login_session['email'])
	if uid is None:
		uid = createUserFromGoogle(login_session)

	login_session['user_id'] = uid;

	output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        #output += login_session['picture']
        #output += ' " style = "width: 150px; height: 150px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
        flash("you are now logged in as %s" % login_session['username'])
	return output


@app.route('/fbdisconnect')
def fbdisconnect():
	facebook_id = login_session['facebook_id']
        #the access token must be included to successfull log out
        access_token = login_session['access_token']
        url = "https://graph.facebook.com/%s/permissions?access_token=%s" %(facebook_id, access_token)
        h = httplib2.Http()
        result = h.request(url, 'DELETE')[1]
	msg = result.split(":")
	tag = result[2:9]
	flag = result[11:15]
	if tag == "success" and flag == "true":
		del login_session['access_token']
		del login_session['facebook_id']
		del login_session['firstname']
		del login_session['lastname']
		del login_session['username']
		del login_session['picture']
		del login_session['email']
		return True
	else:
		return False

@app.route('/gdiconnect')
def gdisconnect():
	access_token = login_session.get('access_token')
	if access_token is None:
		response = make_response(json.dumps('current user not logged int yet'))
		response.headers['Content-Type'] = 'application/json'
		return response

	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' %access_token
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]
	if result['status'] == '200':
		del login_session['access_token']
                del login_session['google_id']
		del login_session['firstname']
		del login_session['lastname']
                del login_session['username']
                del login_session['email']
                del login_session['picture']
		flash("Log out successfully")
		#response = make_response(json.dumps('Successfully disconnected.'), 200)
                #response.headers['Content-Type'] = 'application/json'
                #return response
		return True
	else:
		flash("problem while logout")
		#response = make_response(json.dumps('Failed to revoke token for given user.', 400))
                #response.headers['Content-Type'] = 'application/json'
                #return response	
		return False

@app.route('/logout')
def logout():
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			if (gdisconnect()):
				del login_session['provider']
				flash("You have successfuly logged out")
				redirect('/catalog')
			else:
				flash("Something got wrong, not logged out yet!")
			return redirect('/catalog')

		if login_session['provider'] == 'facebook':
			if (fbdisconnect()):
				del login_session['provider']
				flash("You have successfully logged out")
				return redirect('/catalog')
			else:
				flash("Some thing got wrong, not logged out yet")
				return redirect('/catalog')

	elif 'username' in login_session:
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		flash("You have successfully logged out")
                return redirect('/catalog')

	else:
		flash("Something got worng not logged out yet")
		return redirect('/catalog')
		 

@app.route('/')
@app.route('/catalog')
def catalogHandler():
	categories = session.query(Category).all()
	items = session.query(Item).order_by(Item.id.desc()).limit(5).all()
	allitems = []
	for item in items:
		cat = session.query(Category).filter_by(id = item.category_id).first()
		allitems.append({'category': cat.name, 'item': item.name})


	if 'username' not in login_session:	
		return render_template('publicindex.html', categories=categories, items=allitems)
	else:
		return render_template('index.html', categories=categories, items=allitems)

@app.route('/category', methods=['GET', 'POST'])
def newCategory():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == "GET":
		return render_template("newcategory.html")
	else:
		#todo: add falsh message and stay ont he same page even name already exist
		name = request.form.get("name")
		desc = request.form.get("desc")
		find_name = session.query(Category).filter_by(name=name).first()
		if find_name:
			flash ("category with the same name exist already!")
			render_template("newcategory.html")
		category = Category(name=name, description=desc)
		session.add(category)
		session.commit()
		flash("Category created successfully")
		return render_template("newcategory.html")


@app.route('/item', methods=['GET', 'POST'])
def newItem():
	if 'username' not in login_session:
                return redirect('/login')
	categories = session.query(Category).all()
	if request.method == "GET":
                return render_template("newitem.html", categories=categories)
        else:
                #todo: add falsh message and stay ont he same page even name already exist
                name = request.form.get("name")
                desc = request.form.get("desc")
		cat = request.form.get("select")
		if cat is None:
			return "no category selected!, please select one!"

		cat_name = session.query(Category).filter_by(id=cat).first().name
                find_item = session.query(Item).filter_by(name=name).first()
                if find_item:
                	find_cat = session.query(Category).filter_by(id=find_item.category_id).first()
			if int(find_cat.id) == int(cat):
		        	flash ("item under the same category with the same name exist already!")
				return render_template("newitem.html", categories=categories)
                item = Item(name=name, description=desc, category_id=cat)
                session.add(item)
                session.commit()
		flash("item created successfully!")
                return render_template("newitem.html", categories=categories)

@app.route('/catalog/<string:category_name>/items')
def showItemList(category_name):
	categories = session.query(Category).all()
	category_obj = session.query(Category).filter_by(name=category_name).first()
	items = session.query(Item).filter_by(category_id = category_obj.id).all()
	return render_template('itemlist.html', categories=categories, category=category_name, items=items, count=len(items))


@app.route('/catalog/<string:category_name>/<string:item_name>')
def showItem(category_name, item_name):
	#if user login in show edit and delete button url_for('publicitem.html')
	# otherwies, show the public version url_for('item.html')
	category = session.query(Category).filter_by(name=category_name).first()
	if not category:
		return "No this category %s" %category_name
	item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
	if not item:
		return "No this item: %s under category: %s" %(item_name, category_name)
	
	if 'username' not in login_session:
		return render_template("publicitem.html", item=item, category=category)

	else:
		return render_template("item.html", item=item, category=category)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_name):
	if 'username' not in login_session:
                return redirect('/login')
	if request.method == 'GET':
		category = session.query(Category).filter_by(name=category_name).first()
        	if not category:
                	return "No this category %s" %category_name
        	item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
       	 	if not item:
                	return "No this item: %s under category: %s" %(item_name, category_name)
		
		categories = session.query(Category).all()
                return render_template('edititem.html', categories=categories, category=category, item=item)
        else:	
		category = session.query(Category).filter_by(name=category_name).first()
		item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()	
		name = request.form.get('name')
		desc = request.form.get('desc')
		cate = request.form.get('select')
		if(name):
			item.name = name
		if(desc):
			item.description = desc
		if(cate):
			item.category_id = cate

		session.commit()
		
		return redirect(url_for('catalogHandler'))	

@app.route('/catalog/<string:category_name>/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
	if 'username' not in login_session:
                return redirect('/login')
	
	category = session.query(Category).filter_by(name=category_name).first()
        if not category:
                return "No this category %s" %category_name
        item = session.query(Item).filter_by(category_id=category.id).filter_by(name=item_name).first()
        if not item:
                return "No this item: %s under category: %s" %(item_name, category_name)
	
	if request.method == 'GET':
		return render_template('deleteitem.html', category=category, item=item)
	else:
		session.delete(item)
		session.commit()
		flash("item %s deleted from the database" %item_name)
		return redirect(url_for('catalogHandler'))


@app.route('/catalog.json')
def showAllItmesJSON():
	categories = session.query(Category).all()
	results = []

	for category in categories:
		items = session.query(Item).filter_by(category_id=category.id).all()
		results.append({"id": category.id, "name": category.name, "description": category.description, "items":[item.serialize for item in items]})
			
	return jsonify(catogories = [result for result in results])


#user helper function
def createUserFromGoogle(login_session):
	new_user_profile = User_Profile(first_name = login_session['firstname'], last_name = login_session['lastname'],username=login_session['username'], email=login_session['email'].decode('utf-8'))
	session.add(new_user_profile)
	session.commit()
	user = session.query(User_Profile).filter_by(email=login_session['email']).first();
	new_google_account = Google_Account(user_profile_id=user.id, google_id=login_session['google_id'])
	session.add(new_google_account)
	session.commit()
	return user.id


#user helper function
def createUserFromFacebook(login_session):
        new_user_profile = User_Profile(first_name = login_session['firstname'], last_name = login_session['lastname'],username=login_session['username'], email=login_session['email'].decode('utf-8'))
        session.add(new_user_profile)
        session.commit()
        user = session.query(User_Profile).filter_by(email=login_session['email']).first();
        new_facebook_account = Facebook_Account(user_profile_id=user.id, facebook_id=login_session['google_id'])
        session.add(new_facebook_account)
        session.commit()
        return user.id


def createUser():
	pass

def getUserInfo(user_id):
	user = session.query(User_Profile).filter_by(id=user_id).frist()
	return user

def getUserID(mail):
	try:

		print "is email correct here????"
		print mail
		print type(mail)
		user = session.query(User_Profile).filter_by(email='duanhongyu2010@gmail.com').first()
		print "user here shoul dbe ok"
		print user.id, user.email
		user = session.query(User_Profile).filter_by(email=mail.decode('utf-8')).first()
		print "useer id here"
		print user
		print user.id
		return user.id
	except:
		print "problem while check for user"
		return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
	if request.method == 'GET':
		return render_template('signup.html')
	
	else:
		email = request.form.get('email')
		username = request.form.get('username')
		firstname = request.form.get('firstname')
		lastname = request.form.get('lastname')
		password = request.form.get('pwd')
		password_confirm = request.form.get('pwd_confirm')

		print email
		print "email above"		
		if email is None or email == "" or password is None or password=="" or username is None or username == "":
			print "OK heres"
			return "Missin argument, emial username and password field could not be empty"

		if password != password_confirm:
			return "Password not match"
	
		
		#check if user profile with the same email address exist or not in the database
		user = session.query(User_Profile).filter_by(email=email).first()
		if user is not None:
			flash ("user with email address %s already exist" %email)
			return redirect('signup')
		
		new_user_profile = User_Profile(first_name=firstname, last_name=lastname, username=username, email=email)	
		session.add(new_user_profile)
        	session.commit()
        	user = session.query(User_Profile).filter_by(email=email).first()

		new_user = User(user_profile_id=user.id, username=username, email=email, password_hash=password)
		new_user.hash_password(password)
		session.add(new_user)
		session.commit()
		
		flash ("user created successfully!")
		return redirect('signup')
		

if  __name__ == '__main__':
        app.debug = True
        app.run(host='0.0.0.0', port=5000)
