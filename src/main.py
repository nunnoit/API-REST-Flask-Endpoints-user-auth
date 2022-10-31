#Import List
####################################
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
#Import DB Models
from models import db, User, People, Favorite_People, Planets, Favorite_Planets, Vehicles, Favorite_Vehicles, TokenBlockedList
from datetime import date, time, datetime, timezone
#Import jwt-flask-extended plus ext
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt
#Import Bcrypt
from flask_bcrypt import Bcrypt
####################################

#App+ Settings
app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

#Flask-JWT-Extended Settings
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

#Bcrypt
bcrypt = Bcrypt(app)

#Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

#Generate sitemap with all Endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

#Endpoint User login
@app.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    email = body['email']
    password = body['password']

    user = User.query.filter_by(email=email).first()

    if user is None:
        raise APIException("Error: User does not exist", status_code=401)
    
    # Validate pass & check if match with user password in DB
    if not bcrypt.check_password_hash(user.password, password):
        raise APIException("Error: Username or password do not match", status_code=401)

    access_token = create_access_token(identity= user.id)
    return jsonify({"token": access_token})

# Endpoint user Logout
@app.route('/logout', methods=['get'])
@jwt_required()
def logout():
    print(get_jwt())
    jti=get_jwt()["jti"]
    now = datetime.now(timezone.utc)

    tokenBlocked = TokenBlockedList(token=jti, created_at=now)
    db.session.add(tokenBlocked) #Add token to db to be blacklisted
    db.session.commit()

    return jsonify({"message":"The user has successfully logged out."})

# Endpoint suspend user
@app.route('/ban/<int:user_id>', methods=['PUT'])
@jwt_required()
def user_suspended(user_id):
    if get_jwt_identity() != 1:
        return jsonify({"message":"Operation not allowed"}), 403
        
    user = User.query.get(user_id)
   
    # Check if name come in the body request
    if user.is_active:
        user.is_active = False
        db.session.commit()   
        return jsonify({"message":"User suspended"}), 203
    else:
        user.is_active = True
        db.session.commit()   
        return jsonify({"message":"User is Active"}), 203

# Endpoint get all users
@app.route('/user', methods=['GET'])
def handle_hello():
    users = User.query.all()
    #print(users)
    # (user)=>user.serialize()
    users = list(map(lambda user: user.serialize(), users))
    return jsonify(users), 200

# Endpoint post user
@app.route('/user', methods=['POST'])
def create_new_user():
    body = request.get_json()
    #print(body['username'])
    descripcion = ""
    try:
        if body is None or "email" not in body:
            raise APIException(
                "Invalid: Body is empty or email does not come in the body.", status_code=400)
        if body['email'] is None or body['email'] == "":
            raise APIException("Error: Email is valid.", status_code=400)
        if body['password'] is None or body['password'] == "":
            raise APIException("Error: password is invalid", status_code=400)
        if body['description'] is None or body['description'] == "":
            descripcion = "Error: No description"
        else:
            descripcion = body['description']

        password = bcrypt.generate_password_hash(body['password'],10).decode("utf-8")

        new_user = User(email=body['email'], password=password,
                        is_active=True, description=descripcion)
        users = User.query.all()
        users = list(map(lambda user: user.serialize(), users))

        for i in range(len(users)):
            if (users[i]['email'] == new_user.serialize()['email']):
                raise APIException("Error: User already exists.", status_code=400)

        print(new_user)
        #print(new_user.serialize())
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"mensaje": "User created successfully"}), 201


    except Exception as err:
        db.session.rollback()
        print(err)
        return jsonify({"mensaje": "Error registering user"}), 500

# Endpoint get user by id
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    if user_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    user = User.query.get(user_id)
    if user == None:
        raise APIException("Error: Username does not exist", status_code=400)
    #print(user.serialize())
    return jsonify(user.serialize()), 200

# Endpoint delete user by id
@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user_by_id(user_id):
    if user_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    user = User.query.get(user_id)
    if user == None:
        raise APIException("Error: Username does not exist", status_code=400)
    #print(user.serialize())
    db.session.delete(user)
    db.session.commit()
    return jsonify("The user deleted successfully"), 200

# Endpoint get all people
@app.route('/people', methods=['GET'])
def get_people():
    peoples = People.query.all()
    #print(users)
    peoples = list(map(lambda people: people.serialize(), peoples))
    #print(users)
    return jsonify(peoples), 200

# Endpoint get people by id
@app.route('/people/<int:people_id>', methods=['GET'])
def get_people_by_id(people_id):
    if people_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    person = People.query.get(people_id)
    if person == None:
        raise APIException("Error: Username does not exist", status_code=400)
    return jsonify(person.serialize()), 200

# Endpoint get all planets
@app.route('/planets', methods=['GET'])
def get_planets():
    planets = Planets.query.all()
    planets = list(map(lambda planet: planet.serialize(), planets))
    return jsonify(planets), 200

# Endpoint get planet by id
@app.route('/planet/<int:planet_id>', methods=['GET'])
def get_planet_by_id(planet_id):
    if planet_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    planet = Planets.query.get(planet_id)
    if planet == None:
        raise APIException("Error: The planet does not exist", status_code=400)
    return jsonify(planet.serialize()), 200

# Endpoint get all vehicles
@app.route('/vehicles', methods=['GET'])
def get_vehicles():
    vehicles = Vehicles.query.all()
    vehicles = list(map(lambda vehicle: vehicle.serialize(), vehicles))
    return jsonify(vehicles), 200

# Endpoint get vehicle by id
@app.route('/vehicle/<int:vehicle_id>', methods=['GET'])
def get_vehicle_by_id(vehicle_id):
    if vehicle_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    vehicle = Vehicles.query.get(vehicle_id)
    if vehicle == None:
        raise APIException("Error: The vehicle does not exist", status_code=400)
    return jsonify(vehicle.serialize()), 200

#Endpoint get all favorites from user
@app.route('/user/favorites', methods=['GET'])
def get_favorites():
    favorite_peoples = Favorite_People.query.all()
    favorite_peoples = list(
        map(lambda favorite_people: favorite_people.serialize(), favorite_peoples))
    favorite_planets = Favorite_Planets.query.all()
    favorite_planets = list(
        map(lambda favorite_planet: favorite_planet.serialize(), favorite_planets))
    favorite_vehicles = Favorite_Planets.query.all()
    favorite_vehicles = list(
        map(lambda favorite_vehicle: favorite_vehicle.serialize(), favorite_vehicles))
    favorites_list = favorite_peoples + favorite_planets + favorite_vehicles
    print(favorites_list)
    return jsonify(favorites_list), 200

# Endpoint post people
@app.route('/people', methods=['POST'])
def create_new_person():
    body = request.get_json()
    # Validations
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("Error: name is invalid", status_code=400)

    new_character = People(name=body['name'], height=body['height'], mass=body['mass'], hair_color=body['hair_color'], skin_color=body['skin_color'],
                           eye_color=body['eye_color'], birth_year=body['birth_year'], gender=body['gender'], homeworld=body['homeworld'])
    characters = People.query.all()
    characters = list(map(lambda character: character.serialize(), characters))

    print(new_character)
    #print(new_user.serialize())
    db.session.add(new_character)
    db.session.commit()

    return jsonify({"mensaje": "Character created successfully"}), 201

# Endpoint post planet
@app.route('/planet', methods=['POST'])
def create_new_planet():
    body = request.get_json()
    # Validations
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("Error: name is invalid", status_code=400)

    new_planets = Planets(name=body['name'], diameter=body['diameter'], rotation_Period=body['rotation_Period'], orbital_Period=body['orbital_Period'],
                          gravity=body['gravity'], population=body['population'], climate=body['climate'], terrain=body['terrain'], surface_Water=body['surface_Water'])
    planets = Planets.query.all()
    planets = list(map(lambda planet: planet.serialize(), planets))

    for i in range(len(planets)):
        if (planets[i]['name'] == new_planets.serialize()['name']):
            raise APIException("Error: The planet already exists", status_code=400)

    print(new_planets)
    #print(new_user.serialize())
    db.session.add(new_planets)
    db.session.commit()

    return jsonify({"mensaje": "Planet created successfully."}), 201

# Endpoint post vehicle
@app.route('/vehicle', methods=['POST'])
def create_new_vehicle():
    body = request.get_json()
    # Validations
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("Error: name is invalid", status_code=400)

    new_vehicles = Vehicles(name=body['name'], model=body['model'], vehicle_class=body['vehicle_class'], manufacturer=body['manufacturer'], cost_in_credits=body['cost_in_credits'], length=body['length'],
                            crew=body['crew'], passengers=body['passengers'], max_atmosphering_speed=body['max_atmosphering_speed'], cargo_capacity=body['cargo_capacity'], consumables=body['consumables'])
    vehicles = Vehicles.query.all()
    vehicles = list(map(lambda vehicle: vehicle.serialize(), vehicles))

    for i in range(len(vehicles)):
        if (vehicles[i]['name'] == new_vehicles.serialize()['name']):
            raise APIException("The vehicle already exists", status_code=400)

    print(new_vehicles)
    db.session.add(new_vehicles)
    db.session.commit()

    return jsonify({"mensaje": "Vehicle created successfully"}), 201

# Endpoint delete people by id
@app.route('/people/<int:item_id>', methods=['DELETE'])
def delete_character_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    character = People.query.get(item_id)
    if character == None:
        raise APIException("Error: character does not exist", status_code=400)
    db.session.delete(character)
    db.session.commit()
    return jsonify("Character successfully deleted"), 200

# Endpoint delete planet by id
@app.route('/planet/<int:item_id>', methods=['DELETE'])
def delete_planet_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    planet = Planets.query.get(item_id)
    if planet == None:
        raise APIException("Error: the planet does not exist", status_code=400)
    db.session.delete(planet)
    db.session.commit()
    return jsonify("Planet successfully removed."), 200

# Endpoint vehicle planet by id
@app.route('/vehicle/<int:item_id>', methods=['DELETE'])
def delete_vehicle_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    vehicle = Vehicles.query.get(item_id)
    if vehicle == None:
        raise APIException("Error: The vehicle does not exist.", status_code=400)
    db.session.delete(vehicle)
    db.session.commit()
    return jsonify("Vehicle removed successfully."), 200

# Endpoint DELETE drom FAVORITE people
@app.route('/favorites/people/<int:item_id>', methods=['DELETE'])
def delete_favorite_character_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    item = People.query.get(item_id)
    if item == None:
        raise APIException("Error: character does not exist", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Successfully deleted character."), 200

# Endpoint DELETE drom FAVORITE planet
@app.route('/favorites/planet/<int:item_id>', methods=['DELETE'])
def delete_favorite_planet_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    item = Planets.query.get(item_id)
    if item == None:
        raise APIException("Error: the planet does not exist", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Planet successfully removed."), 200

# Endpoint DELETE drom FAVORITE vehicle
@app.route('/favorites/vehicle/<int:item_id>', methods=['DELETE'])
def delete_favorite_vehicle_by_id(item_id):
    if item_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    item = Vehicles.query.get(item_id)
    if item == None:
        raise APIException("Error: The vehicle does not exist", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Vehicle removed successfully."), 200


#Endpoint Update people
@app.route('/people/<int:people_id>', methods=['PUT'])
def put_people_by_id(people_id):
    if people_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    person = People.query.get(people_id)  
    if person == None:
        raise APIException("Error: Username does not exist", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    # Check for body if empty (request)
    if not body['name'] is None:
        person.name = body['name']
    db.session.commit()
    return jsonify(person.serialize()), 200

#Endpoint Update planet
@app.route('/planet/<int:planet_id>', methods=['PUT'])
def put_planet_by_id(planet_id):
    if planet_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    planet = Planets.query.get(planet_id)  
    if planet == None:
        raise APIException("Error: the planet does not exist", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    # Check for body if empty (request)
    if not body['name'] is None:
        planet.name = body['name']
    db.session.commit()
    return jsonify(planet.serialize()), 200

#Endpoint Update vehicle
@app.route('/vehicle/<int:vehicle_id>', methods=['PUT'])
def put_vehicle_by_id(vehicle_id):
    if vehicle_id == 0:
        raise APIException("Error: id cannot be equal to 0", status_code=400)
    vehicle = Vehicles.query.get(vehicle_id)  # Search by id
    if vehicle == None:
        raise APIException("Error: The vehicle does not exist", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    # Check for body if empty (request)
    if not body['name'] is None:
        vehicle.name = body['name']
    db.session.commit()
    return jsonify(vehicle.serialize()), 200

#Endpoint Search people
@app.route('/people/busqueda', methods=['POST'])
def busqueda_people():
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Error: body is empty", status_code=400)
    if not body['name'] is None:
        # va a encontrar todas las coincidencias
        found = People.query.filter(People.name == body['name']).all()
        found = list(map(lambda item: item.serialize(), found))
        print(found)
    if found == None:
        raise APIException("Error: character does not exist", status_code=400)
    return jsonify(found), 200

#Endpoint VIP Area (protected by user Token)
@app.route('/vip', methods=['post']) 
@jwt_required() # <--- Restricted by token
def hello_protected():
    #claims = get_jwt()
    print("User ID: ", get_jwt_identity())
    user = User.query.get(get_jwt_identity()) # User id in the DB

    #get_jwt() Returns a dictionary
    jti=get_jwt()["jti"] 

    tokenBlocked = TokenBlockedList.query.filter_by(token=jti).first()

    if isinstance(tokenBlocked, TokenBlockedList):
        return jsonify(msg="Access denied")

    response_body={
        "message":"Token is valid :)",
        "user_id": user.id,
        "user_email": user.email,
        "description": user.description
    }

    return jsonify(response_body), 200


# <THE END/>
# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
