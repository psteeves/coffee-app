from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import json

from .database.models import setup_db, Drink, db
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)


@app.route("/drinks")
def drinks():
    drinks = db.session.query(Drink).order_by(Drink.id).all()
    return jsonify({"drinks": [drink.short() for drink in drinks]})


@app.route("/drinks-detail")
@requires_auth("get:drinks-detail")
def drinks_detail(jwt):
    drinks = db.session.query(Drink).order_by(Drink.id).all()
    return jsonify({"drinks": [drink.long() for drink in drinks]})


@app.route("/drinks", methods=["POST"])
@requires_auth("post:drinks")
def post_drinks(jwt):
    drink_body = request.get_json()
    drink = Drink(title=drink_body["title"], recipe=json.dumps(drink_body["recipe"]))
    drink.insert()
    return jsonify({"drinks": [drink.long()]})


@app.route("/drinks/<int:drink_id>", methods=["PATCH"])
@requires_auth("patch:drinks")
def patch_drinks(jwt, drink_id):
    drink_body = request.get_json()
    drink = db.session.query(Drink).filter(Drink.id == drink_id).one_or_none()
    if drink is None:
        abort(404)

    drink.title = drink_body["title"]
    drink.recipe = json.dumps(drink_body["recipe"])
    drink.update()
    return jsonify({"drinks": [drink.long()]})


@app.route("/drinks/<int:drink_id>", methods=["DELETE"])
@requires_auth("delete:drinks")
def delete_drinks(jwt, drink_id):
    drink = db.session.query(Drink).filter(Drink.id == drink_id).one_or_none()
    if drink is None:
        abort(404)

    drink.delete()
    return jsonify({"delete_id": drink_id})


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({"error": 422, "message": "unprocessable"}), 422


@app.errorhandler(404)
def unprocessable(error):
    return jsonify({"error": 404, "message": "resource not found"}), 404


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response
