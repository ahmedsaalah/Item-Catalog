from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc,desc
from sqlalchemy.orm import sessionmaker
from database_setup import  Base,Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from pprint import pprint
from functools import wraps


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog App"


def login_required(f):
    """ Checks if the user is logged in or not """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You need to be logged in to add a new item.")
            return redirect(url_for('getMainPage'))
    return decorated_function


def checkIfTitleExists(title):
    """ Checks if an item exists with the same unique title in db """
    results = session.query(Item).filter_by(name=title).all()
    return len(results) > 0

# Connect to Database and create database session

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', state=state)

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        print(login_session)
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('routeToMain'))
    else:
        flash("You were not logged in")
        return redirect(url_for('routeToMain'))


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print(request.data)
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("""""""""""""""""""""""""""""""""""""""""""""""""""""""""""")
    print(result)

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    shoghl=json.loads(token)
    print "access the actual token received %s " % shoghl["access_token"]


    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % shoghl["access_token"]
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    # print("====================session------------")
    # print(login_session['username'])
    # print("====================session------------")
    data = json.loads(result)
    pprint(data)
    print("======================")
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    # stored_token = token.split("=")[1]
    login_session['access_token'] = shoghl["access_token"]

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?access_token=%s&redirect=0&height=200&width=200' % shoghl["access_token"]
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print(request.args.get('state'))
    print(login_session['state'])
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        print("------------------------------------------------------------------------")
        print(oauth_flow)
        credentials = oauth_flow.step2_exchange(code)
        print(credentials)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)

    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    stored_access_token = None
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = "google"
    userID=getUserID(data['email'])
    if(userID is None):
        userID=createUser(login_session)

    
    login_session['user_id'] = userID
    
    login_session['url']='https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials.access_token

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response



def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
def routeToMain():
    """ Main Page """
    return redirect(url_for('getMainPage'))
@app.route('/catalog/JSON')    
def getCatalog():
    """ Returns JSON version of the catalog """
    output_json = []
    categories = session.query(Category).all()
    for category in categories:
        print(category.id)
        items = session.query(Item).filter_by(category_id=category.id)
        category_output = {}
        category_output["id"] = category.id
        category_output["name"] = category.name
        pprint(items)
        category_output["items"] = [i.serialize for i in items]
        pprint(category_output)
        output_json.append(category_output)
    return jsonify(Categories=output_json)


@app.route('/catalog', methods=['GET', 'POST'])         
def getMainPage():
    """ Handler for main page, includes auth, session management """
    try:
        user = login_session['username']
    except KeyError:
        user = None
    if request.method == 'GET':
        STATE = ''.join(random.choice(string.ascii_uppercase +
            string.digits) for x in xrange(32))
        login_session['state'] = STATE
        categories = session.query(Category).all()
        latest_items = session.query(Item).order_by(desc(Item.created)).all()
        
        category_names = {}
        for category in categories:
            category_names[category.id] = category.name
        if len(latest_items) == 0:
            flash("No items found")
      
        
        return render_template(
            'main.html', categories=categories, items=latest_items,
            category_names=category_names, user=user, state=STATE
        )
    else:
        print ("Starting authentication")
        if request.args.get('state') != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Obtain authorization code
        code = request.data

        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            print "Token's client ID does not match app's."
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get('credentials')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'),
                                     200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        login_session['access_token'] = credentials.access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()

        login_session['username'] = data['name']

        flash("you are now logged in as %s" % login_session['username'])
        return redirect(url_for('getMainPage'))
@app.route('/catalog/categories/<category_name>/')
def getCategoryItems(category_name):
    """ Returns items for a given category name """
    categories = session.query(Category).all()
    selected_category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=selected_category.id).all()
    category_names = {}
    for category in categories:
        category_names[category.id] = category.name
    if len(items) == 0:
        flash("No items found in this category")
    try:
        user = login_session['username']
    except KeyError:
        user = None
    
    return render_template(
        'category_detail.html', selected_category=selected_category,  user=user,
        items=items, categories=categories, category_names=category_names
    )
@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def newItem():
    """ Handles the creation of a new item """
    categories = session.query(Category).all()
    try:
        user = login_session['username']
    except KeyError:
        user = None
    if request.method == 'POST':
        title = request.form['title']
        if checkIfTitleExists(title):
            flash("Please enter a different title. Item " +
                title + " already exists.")
            return redirect(url_for('newItem'))
        print(request.form['category_id'])
        pprint(login_session)
        newItem = Item(name=title,
                description = request.form['description'],
               category_id = request.form['category_id'],
               
               user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('getMainPage'))
    else:
        return render_template(
            'create_item.html', categories=categories, user=user
        )

@app.route('/catalog/items/<item_title>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item_title):
    """ Handles updating an existing item """
    editedItem = session.query(Item).filter_by(name=item_title).one()
    category = session.query(Category).filter_by(id=editedItem.category_id).one()
    categories = session.query(Category).all()
    if request.method == 'POST':
        if request.form['title']:
            title = request.form['title']
            if item_title != title and checkIfTitleExists(title):
                flash("Please enter a different title. Item " +
                    title + " already exists.")
                return redirect(url_for('editItem', item_title=item_title))
            editedItem.title = title
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category_id']:
            editedItem.category_id = request.form['category_id']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('getMainPage'))
    else:
        user = login_session['username']
        return render_template(
            'edit_item.html', item=editedItem, category=category,
            categories=categories, user=user
        )

@app.route('/catalog/items/<item_title>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item_title):
    """ Deletes an item given its unique title """
    if request.method == 'POST':
        itemToDelete = session.query(Item).filter_by(name=item_title).one()
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('getMainPage'))
    else:
        user = login_session['username']
        return render_template(
            'delete_item.html', item_title = item_title, user=user
        )


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)