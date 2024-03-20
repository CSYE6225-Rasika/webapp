
from flask import Flask, jsonify, request, abort
from flask_bcrypt import Bcrypt
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy_utils import database_exists, create_database
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import re
from functools import wraps
from datetime import datetime
import base64
import uuid
import logging
import json
import google.cloud.logging



# Configure logging client
client = google.cloud.logging.Client()
client.get_default_handler()
client.setup_logging()

# Define custom formatter to output logs as JSON
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'severity': record.levelname,
            'message': record.getMessage(),
        }
        return json.dumps(log_data)

# Create logger and set formatter
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)  # Set log level to INFO


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:@localhost:5432/user_databse'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    __tablename__ = 'user_info'

    id = db.Column(db.String(36), primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(60), unique=True, nullable=False)
    account_created = db.Column(db.DateTime, default=datetime.utcnow)
    account_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)





@app.route('/v1/user', methods=['POST'])
def create_user():
    data = request.json

    

    required_fields = ['first_name', 'last_name', 'password', 'username']
    for field in required_fields:
        if field not in data:
            logger.error(f'Missing {field} field', extra={'data': data})
            return jsonify({'message': f'Missing {field} field'}), 400
        if field == 'username' and not re.match(r"[^@]+@[^@]+\.[^@]+", data['username']):
            logger.error('Invalid email format', extra={'username': data.get('username', '')})
            return jsonify({'message': 'Invalid email format'}), 400
    
    

    
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        logger.error('User with this username already exists', extra={'username': data['username']})
        return jsonify({'message': 'User with this username already exists'}), 400

    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    
    new_user = User(
        id=str(uuid.uuid4()),
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=hashed_password,
        username=data['username']
    )

    
    db.session.add(new_user)
    db.session.commit()

    logger.info('User created successfully', extra={'user': new_user.username})
    return jsonify({'message': 'User created successfully'}), 201

def basic_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            logger.error('Unauthorized access', extra={'username': auth.username})
            return jsonify({'message': 'Unauthorized access'}), 401
        return f(*args, **kwargs)
    return decorated

def check_auth(username, password):
    
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return True
    return False


@app.route('/v1/user/self', methods=['GET'])
@basic_auth_required
def get_user_info():
    
    username = request.authorization.username

    
    user = User.query.filter_by(username=username).first()

    
    if user:
        
        user_info = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'account_created': user.account_created.isoformat(),
            'account_updated': user.account_updated.isoformat()
        }
        logger.info('User info retrieved successfully', extra={'username': username})
        return jsonify(user_info), 200
    else:
        logger.error('User not found', extra={'username': username})
        return jsonify({'message': 'User not found'}), 404

@app.route('/v1/user/self', methods=['PUT'])
@basic_auth_required
def update_user_info():
    data = request.json

    
    required_fields = ['first_name', 'last_name', 'password', 'username']
    for field in required_fields:
        if field not in data:
            logger.error(f'Missing {field} field', extra={'data': data})
            return jsonify({'message': f'Missing {field} field'}), 400

    
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        logger.error('User not found', extra={'username': data['username']})
        return jsonify({'message': 'User not found'}), 400

    user.first_name = data['first_name']
    user.last_name = data['last_name']
    user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    db.session.commit()
    logger.info('User info updated successfully', extra={'username': data['username']})
    return '', 204


def check_database():
    try:
        database_uri = app.config['SQLALCHEMY_DATABASE_URI']
        engine = create_engine(database_uri)
        
        if not database_exists(engine.url):
            create_database(engine.url)
            print("Database 'user_database' created successfully.")
        else:
            print("Database 'user_database' already exists.")

    except OperationalError as e:
        print("Error creating database:", str(e))

check_database()


@app.route('/healthz', methods=['HEAD', 'OPTIONS'])
@basic_auth_required
def handle_invalid_methods():
    logger.error('Method Not Allowed')
    return jsonify(message="Method Not Allowed"), 405


@app.route('/healthz', methods=['GET'])
@basic_auth_required
def health_check_database():
    if request.method != 'GET':
        logger.error('Method Not Allowed', extra={'method': request.method})
        abort(405)
    try:
        print("Database URI:", app.config['SQLALCHEMY_DATABASE_URI'])
        print("Executing database query.......")
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        with engine.connect() as connection:
            query = text('SELECT 1;')
            result = connection.execute(query)
            print("Query Executed!")
            # Fetching result is optional, but you can do so if needed
            result.fetchone()

        response = jsonify(status='ok', message='OK')
        logger.info("Database Service is healthy")
        response.status_code = 200
        response.headers['Cache-Control'] = 'no-cache'
        return response
    except OperationalError as e:
        logger.critical('Database Service Unavailable')
        print(f"Error executing database query: {str(e)}")
        error_response = jsonify(status='error', message='Service Unavailable')
        error_response.status_code = 503
        error_response.headers['Cache-Control'] = 'no-cache'
        return error_response

def main():
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)


if __name__ == '__main__':

    main()

    
#REFERENCES
#API — Flask Documentation (3.0.X). (n.d.). https://flask.palletsprojects.com/en/3.0.x/api/
#Flask-SQLAlchemy — Flask-SQLAlchemy Documentation (3.1.x). (n.d.). https://flask-sqlalchemy.palletsprojects.com/en/3.1.x/
#https://www.redhat.com/sysadmin/postgresql-setup-use-cases
#Flask interfaces — API — Flask API. (n.d.). https://tedboy.github.io/flask/interface_api.html
#https://flask-jwt-extended.readthedocs.io/en/stable/custom_decorators.html

