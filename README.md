# Item Catalog 

This repository implements the third project (Item Catalog App) in the Udacity Full Stack Nanodegree program.

A user of this project can add, edit, and delete items belonging to a particular category.  

Authentication is handled by Google OAuth.  User can only edit or delete items they created.

# Prerequisites
Requires Python, pip, and git.

# How to Install
To download and install this program, you will need git installed.

At the command line, enter:
```
git clone https://github.com/ahmedsaalah/Item-Catalog.git
```

Change directory to fs_proj3_item_catalog.

# How to Use Google Authentication Services
You need to supply a client_secret.json file. You can create an application to use
Google's OAuth service at https://console.developers.google.com. 

Instructions are available at Udacity's Authentication & Authorization: OAuth -- Implementing Web Security with OAuth 2.0.
You can find the course at https://www.udacity.com/course/authentication-authorization-oauth--ud330

After creating and downloading your client_secret.json file, move it to the 
fs_proj3_item_catalog directory so it is accessible to the Item Catalog application.

# How to Initialize Database and Load Initial Categories
To initialize the SQLite database (create empty tables) enter
```
python database_setup.py
```

To load the initial sporting good categories enter
```
python database_seed.py
```

# Starting Application
To start the application enter:
```
python project.py
```

Then bring up a browser and point it to localhost:5000.

# Adding, Editing, and Deleting Items
Adding, editing, and deleting items requires the user to log in. 
Logins are handled by Google OAuth.  


