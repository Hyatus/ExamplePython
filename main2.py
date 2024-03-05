from flask import Flask, jsonify, request
from functools import wraps
from ldap3 import Server, Connection, ALL
import jwt 
import datetime
import jaydebeapi
import jpype
import os 
app.config['DRIVER_JDBC'] = os.getenv('DRIVER_JDBC')
app.config['CONN_STRING'] = os.getenv('CONN_STRING')
app.config['USER'] = os.getenv('USER')
app.config['LOG4J'] = os.getenv('LOG4J')
app.config['SERVER_LDAP'] = os.getenv('SERVER_LDAP')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
import json
import querys
import pyodbc
from flask_cors import CORS
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['JAVA_SDK'] = os.getenv('JAVA_SDK')
app.config['DRIVER_JDBC'] = os.getenv('DRIVER_JDBC')
app.config['CONN_STRING'] = os.getenv('CONN_STRING')
app.config['USER'] = os.getenv('USER')
app.config['LOG4J'] = os.getenv('LOG4J')
app.config['SERVER_LDAP'] = os.getenv('SERVER_LDAP')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
 
os.environ["JAVA_HOME"] =app.config['JAVA_SDK']
driver_path = app.config['DRIVER_JDBC']
conn_string = app.config['CONN_STRING']
username = app.config['USER']
password = app.config['PASS']
log4j = app.config['LOG4J']
ServerLDAP = app.config['SERVER_LDAP']
SECRET_KEY = app.config['SECRET_KEY']

jpype.startJVM("-Djava.class.path={}".format(driver_path),log4j)

def verificarToken(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "No se ha proporcionado un token"}), 403
        try:
            return jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token invalido"}), 403
        
        return f(*args, **kwargs)
    return decorator

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    password1 = data[password
    password2 = data[password
    password3 = data[password
    password4 = data[password
    password5 = data[password
    
    username += 'dominio.com.org'
    try:
        with Connection(ServerLDAP, user=username, password=password, auto_bind=True):
            print("Login exitoso")
            token = jwt.encode({'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, SECRET_KEY)
            print(token)
            return jsonify({'token': token})
    except Exception as e:
        print(e)
        return jsonify({'error': 'Credenciales incorrectas'})

@app.route('/validaToken',methods=['GET'])
@verificarToken
def validaToken():
    return jsonify({"mensaje": "Token valido"})
