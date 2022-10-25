import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, People, Favorite_People, Planets, Favorite_Planets, Vehicles, Favorite_Vehicles


#Settings
app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
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

# Endpoint get all users
@app.route('/user', methods=['GET'])
def handle_hello():
    users = User.query.all()
    #print(users)
    # (user)=>user.serialize()
    users = list(map(lambda user: user.serialize(), users))
    #print(users)
    response_body = {
        "msg": "Hello, this is your GET /user response "
    }
    return jsonify(users), 200

# Endpoint post user
@app.route('/user', methods=['POST'])
def create_new_user():
    body = request.get_json()
    #print(body['username'])
    descripcion = ""

    if body is None or "email" not in body:
        raise APIException(
            "Body está vacío o email no viene en el body, es inválido", status_code=400)
    if body['email'] is None or body['email'] == "":
        raise APIException("email es inválido", status_code=400)
    if body['password'] is None or body['password'] == "":
        raise APIException("password es inválido", status_code=400)
    if body['description'] is None or body['description'] == "":
        descripcion = "no hay descripción"
    else:
        descripcion = body['description']

    new_user = User(email=body['email'], password=body['password'],
                    is_active=True, description=descripcion)
    users = User.query.all()
    users = list(map(lambda user: user.serialize(), users))

    for i in range(len(users)):
        if (users[i]['email'] == new_user.serialize()['email']):
            raise APIException("El usuario ya existe", status_code=400)

    print(new_user)
    #print(new_user.serialize())
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"mensaje": "Usuario creado exitosamente"}), 201

# Endpoint get user by id
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    if user_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    user = User.query.get(user_id)
    if user == None:
        raise APIException("El usuario no existe", status_code=400)
    #print(user.serialize())
    return jsonify(user.serialize()), 200

# Endpoint delete user by id
@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user_by_id(user_id):
    if user_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    user = User.query.get(user_id)
    if user == None:
        raise APIException("El usuario no existe", status_code=400)
    #print(user.serialize())
    db.session.delete(user)
    db.session.commit()
    return jsonify("usuario eliminado exitosamente"), 200

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
        raise APIException("Id no puede ser igual a 0", status_code=400)
    person = People.query.get(people_id)
    if person == None:
        raise APIException("El usuario no existe", status_code=400)
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
        raise APIException("Id no puede ser igual a 0", status_code=400)
    planet = Planets.query.get(planet_id)
    if planet == None:
        raise APIException("El planeta no existe", status_code=400)
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
        raise APIException("Id no puede ser igual a 0", status_code=400)
    vehicle = Vehicles.query.get(vehicle_id)
    if vehicle == None:
        raise APIException("El vehículo no existe", status_code=400)
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
        raise APIException("Body está vacío", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("name es inválido", status_code=400)

    new_character = People(name=body['name'], height=body['height'], mass=body['mass'], hair_color=body['hair_color'], skin_color=body['skin_color'],
                           eye_color=body['eye_color'], birth_year=body['birth_year'], gender=body['gender'], homeworld=body['homeworld'])
    characters = People.query.all()
    characters = list(map(lambda character: character.serialize(), characters))

    # for i in range(len(characters)):
    #     if(characters[i]['name']==new_character.serialize()['name']):
    #         raise APIException("El personaje ya existe" , status_code=400)

    print(new_character)
    #print(new_user.serialize())
    db.session.add(new_character)
    db.session.commit()

    return jsonify({"mensaje": "Personaje creado exitosamente"}), 201

# Endpoint post planet
@app.route('/planet', methods=['POST'])
def create_new_planet():
    body = request.get_json()
    # Validations
    if body is None:
        raise APIException("Body está vacío", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("name es inválido", status_code=400)

    new_planets = Planets(name=body['name'], diameter=body['diameter'], rotation_Period=body['rotation_Period'], orbital_Period=body['orbital_Period'],
                          gravity=body['gravity'], population=body['population'], climate=body['climate'], terrain=body['terrain'], surface_Water=body['surface_Water'])
    planets = Planets.query.all()
    planets = list(map(lambda planet: planet.serialize(), planets))

    for i in range(len(planets)):
        if (planets[i]['name'] == new_planets.serialize()['name']):
            raise APIException("El planeta ya existe", status_code=400)

    print(new_planets)
    #print(new_user.serialize())
    db.session.add(new_planets)
    db.session.commit()

    return jsonify({"mensaje": "Planeta creado exitosamente"}), 201

# Endpoint post vehicle
@app.route('/vehicle', methods=['POST'])
def create_new_vehicle():
    body = request.get_json()
    # Validations
    if body is None:
        raise APIException("Body está vacío", status_code=400)
    if body['name'] is None or body['name'] == "":
        raise APIException("name es inválido", status_code=400)

    new_vehicles = Vehicles(name=body['name'], model=body['model'], vehicle_class=body['vehicle_class'], manufacturer=body['manufacturer'], cost_in_credits=body['cost_in_credits'], length=body['length'],
                            crew=body['crew'], passengers=body['passengers'], max_atmosphering_speed=body['max_atmosphering_speed'], cargo_capacity=body['cargo_capacity'], consumables=body['consumables'])
    vehicles = Vehicles.query.all()
    vehicles = list(map(lambda vehicle: vehicle.serialize(), vehicles))

    for i in range(len(vehicles)):
        if (vehicles[i]['name'] == new_vehicles.serialize()['name']):
            raise APIException("El vehículo ya existe", status_code=400)

    print(new_vehicles)
    db.session.add(new_vehicles)
    db.session.commit()

    return jsonify({"mensaje": "Vehículo creado exitosamente"}), 201

# Endpoint delete people by id
@app.route('/people/<int:item_id>', methods=['DELETE'])
def delete_character_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    character = People.query.get(item_id)
    if character == None:
        raise APIException("El personaje no existe", status_code=400)
    db.session.delete(character)
    db.session.commit()
    return jsonify("personaje eliminado exitosamente"), 200

# Endpoint delete planet by id
@app.route('/planet/<int:item_id>', methods=['DELETE'])
def delete_planet_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    planet = Planets.query.get(item_id)
    if planet == None:
        raise APIException("El planeta no existe", status_code=400)
    db.session.delete(planet)
    db.session.commit()
    return jsonify("planeta eliminado exitosamente"), 200

# Endpoint vehicle planet by id
@app.route('/vehicle/<int:item_id>', methods=['DELETE'])
def delete_vehicle_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    vehicle = Vehicles.query.get(item_id)
    if vehicle == None:
        raise APIException("El vehículo no existe", status_code=400)
    db.session.delete(vehicle)
    db.session.commit()
    return jsonify("vehículo eliminado exitosamente"), 200

# Endpoint DELETE drom FAVORITE people
@app.route('/favorites/people/<int:item_id>', methods=['DELETE'])
def delete_favorite_character_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    item = People.query.get(item_id)
    if item == None:
        raise APIException("El personaje no existe", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Personaje eliminado exitosamente"), 200

# Endpoint DELETE drom FAVORITE planet
@app.route('/favorites/planet/<int:item_id>', methods=['DELETE'])
def delete_favorite_planet_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    item = Planets.query.get(item_id)
    if item == None:
        raise APIException("El planeta no existe", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Planeta eliminado exitosamente"), 200

# Endpoint DELETE drom FAVORITE vehicle
@app.route('/favorites/vehicle/<int:item_id>', methods=['DELETE'])
def delete_favorite_vehicle_by_id(item_id):
    if item_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    item = Vehicles.query.get(item_id)
    if item == None:
        raise APIException("El vehículo no existe", status_code=400)
    db.session.delete(item)
    db.session.commit()
    return jsonify("Vehículo eliminado exitosamente"), 200


#Endpoint Update people
@app.route('/people/<int:people_id>', methods=['PUT'])
def put_people_by_id(people_id):
    if people_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    person = People.query.get(people_id)  # Search by id
    if person == None:
        raise APIException("El usuario no existe", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Body está vacío", status_code=400)
    # Check for body if empty (request)
    if not body['name'] is None:
        person.name = body['name']
    db.session.commit()
    return jsonify(person.serialize()), 200

#Endpoint Update planet
@app.route('/planet/<int:planet_id>', methods=['PUT'])
def put_planet_by_id(planet_id):
    if planet_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    planet = Planets.query.get(planet_id)  # Search by id
    if planet == None:
        raise APIException("El planeta no existe", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Body está vacío", status_code=400)
    # Check for body if empty (request)
    if not body['name'] is None:
        planet.name = body['name']
    db.session.commit()
    return jsonify(planet.serialize()), 200

#Endpoint Update vehicle
@app.route('/vehicle/<int:vehicle_id>', methods=['PUT'])
def put_vehicle_by_id(vehicle_id):
    if vehicle_id == 0:
        raise APIException("Id no puede ser igual a 0", status_code=400)
    vehicle = Vehicles.query.get(vehicle_id)  # Search by id
    if vehicle == None:
        raise APIException("El vehiculo no existe", status_code=400)
    body = request.get_json()
    #Validation
    if body is None:
        raise APIException("Body está vacío", status_code=400)
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
        raise APIException("Body está vacío", status_code=400)
    if not body['name'] is None:
        # va a encontrar todas las coincidencias
        found = People.query.filter(People.name == body['name']).all()
        found = list(map(lambda item: item.serialize(), found))
        print(found)
    if found == None:
        raise APIException("El personaje no existe", status_code=400)
    return jsonify(found), 200


# <THE END/>
# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
