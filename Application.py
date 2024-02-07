from flask  import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text 



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres@localhost:5432/user_ip_mapping'
db = SQLAlchemy(app)


@app.route('/healthz',methods=['GET','PUT','POST','PATCH','DELETE','OPTIONS'])
def health_check_database():
	if request.data or request.args:
        	return jsonify(error='Bad Request', message='Payload/Query Parameters Not Allowed for this API!'), 400
        
    
	try:
    		if request.method == 'GET':  
        		print("Database URI:{app.config['SQLALCHEMY_DATABASE_URI']}")
        		print("Executing database query.......")
        		db.session.execute(text('SELECT 1;'))
        		print("Query Executed!")
        		Get_response = jsonify(status='ok', message='OK')
        		Get_response.status_code = 200
        		Get_response.headers['Cache-Control'] = 'no-cache'
        		return Get_response
        	
        	
    		else:
        		send_message =  jsonify(status='error', message='Method Not Allowed')
        		send_message.status_code = 405
        		send_message.headers['Cache-Control'] ='no-cache'
        		return send_message

	except Exception as e:
    		print(f"Error executing database query: {str(e)}")
    		error_response = jsonify(status='error', message='Service Unavailable')
    		error_response.status_code =503
    		error_response.headers['Cache-Control'] ='no-cache'
    		return error_response
if __name__  ==  '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
#REFERENCES
#API — Flask Documentation (3.0.X). (n.d.). https://flask.palletsprojects.com/en/3.0.x/api/
#Flask-SQLAlchemy — Flask-SQLAlchemy Documentation (3.1.x). (n.d.). https://flask-sqlalchemy.palletsprojects.com/en/3.1.x/
#https://www.redhat.com/sysadmin/postgresql-setup-use-cases
#Flask interfaces — API — Flask API. (n.d.). https://tedboy.github.io/flask/interface_api.html
