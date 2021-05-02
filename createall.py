from webserver import create_app, db

app = create_app()

db.drop_all(app=app)
db.create_all(app=app)
