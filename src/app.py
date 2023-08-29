"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from werkzeug.security -> Modulo de la gente que creo flask
from werkzeug.security import generate_password_hash, check_password_hash

# generate_password_hash(password_string) -> encriptado(string)
# check_password_hash(contraseña_encriptada, password_string) -> True(si son iguales) | False(Si son diferentes)

# Autenticacion del usuario
# Register ->
# Encriptas la contraseña

# login | Iniciar sesión
# Generas el token de autenticacion
# Rutas protegidas
#   -> Publicar un post
#   -> Hacer un comentario

app = Flask(__name__)
app.url_map.strict_slashes = False

db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Agregamos la clave secreta de jwt
app.config['JWT_SECRET_KEY'] = os.environ.get('FLASK_APP_KEY')

MIGRATE = Migrate(app, db)

# Envolvemos nuestra aplicacion con JWTManager()
jwt = JWTManager(app)

db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/register', methods=['POST'])
def register_user():
    # Necesitamos recibir un email y un password

    # Accedemos al body(json) de nuestra solicitud
    data = request.get_json() 

    data_email = data.get("email", None)
    data_password = data.get("password", None)

    if not data_email or not data_password:
        # 400 -> bad request
        return jsonify({"error": "all fields required"}), 400

    hashed_password = generate_password_hash(data_password)

    new_user = User(email=data_email, password=hashed_password, is_active=True)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify("Usuario creado con exito!"), 201
    
    except Exception as error:
        db.session.rollback()
        return jsonify(error), 500
    

@app.route("/login", methods=['POST'])
def login_user():
    data = request.get_json()

    data_email = data.get("email", None)
    data_password = data.get("password", None)
    if not data_email or not data_password:
        return jsonify({"error": "All fields required"}), 400
    
    user_login =  User.query.filter_by(email = data_email).first()
    if not user_login:
        return jsonify({"error": "Invalid Email"}), 400
    
    password_match = check_password_hash(user_login.password, data_password)
    if password_match:
        # Token = id del usuario {"id":  1}
        # INFORMACION QUE RECIBIMOS CUANDO USAMOS get_jwt_identity
        token_data = {"id": user_login.id}
        print("data token:", token_data)
        user_token = create_access_token(token_data)
        print("JWT_TOKEN:", user_token)
        return jsonify({"token": user_token})
    else:
        return jsonify({"error": "Contraseña invalida"}), 401

# Ruta Privada
@app.route("/private", methods=["GET"])
@jwt_required() # ESTA RUTA NECESITA UN TOKEN!
def get_private_data():
    return jsonify({"data": "informacion super confidencial"})

# INSTAGRAM
@app.route("/profile", methods=['GET'])
@jwt_required()
def get_saved_posts():
    # Extrayendo la informacion del usuario de el token que recibo
    user_data = get_jwt_identity()
    print("user_data:", user_data)
    # Filtramos nuestros usuarios para buscar los detalles
    current_user = User.query.get(user_data.get("id"))
    return jsonify({"user": current_user.serialize()}), 200

if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
