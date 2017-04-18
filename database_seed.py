from flask import Flask, render_template, request, redirect, url_for, jsonify
from sqlalchemy import *
from database_setup import *
from sqlalchemy.orm import sessionmaker

"""Used for seeding the database for testing and dev purposes"""
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


user = User(name="ahmaaaaa", email="a7mad@live.com")

session.add(user)
session.commit()



Category1=Category(name="sports")
session.add(Category1)
session.commit()
Category1=Category(name="food")
session.add(Category1)
session.commit()
Category1=Category(name="fun")
session.add(Category1)
session.commit()


sport = Item(user_id=1, name="rugby", description="Juicy grilled chicken patty with tomato mayo and lettuce",
        category_id =1)

session.add(sport)
session.commit()

food = Item(user_id=1, name="burger", description="Juicy grilled chicken patty with tomato mayo and lettuce",
        category_id =2)

session.add(food)
session.commit()

food = Item(user_id=1, name="Pizza", description="Juicy grilled chicken patty with tomato mayo and lettuce",
        category_id =2)

session.add(food)
session.commit()

fun = Item(user_id=1, name="running", description="Juicy grilled chicken patty with tomato mayo and lettuce",
        category_id =3)

session.add(fun)
session.commit()
