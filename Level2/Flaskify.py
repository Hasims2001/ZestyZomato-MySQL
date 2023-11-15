from flask import Flask, request, jsonify
import json, os, datetime
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import jwt
from passlib.hash import pbkdf2_sha256 
app = Flask(__name__)
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
app.secret_key = os.getenv('APP_SECRET')
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

user_team_association = db.Table('user_team_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('team_id', db.Integer, db.ForeignKey('team.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80),  nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    token= db.Column(db.String(500), default="", nullable=True)
    Task = db.relationship('Task', backref='user', lazy=True)
    teams = db.relationship('Team', secondary='user_team_association', backref='members', lazy='dynamic')
    

    # def __init__(self, username, email,  password, Task, teams, role, token):
    #     self.username = username
    #     self.email = email
    #     self.password = password
    #     self.Task = Task
    #     self.teams = teams
    #     self.role = role
    #     self.token = token


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    due_date = db.Column(db.String(20))
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


with app.app_context():
    db.create_all()


@app.route('/', methods=['GET'])
def welcome():
    return jsonify({'message': "Welcome to Flaskify"})


@app.route("/login", methods=['POST'])
def loginUser():
    try:
        data = request.get_json()
        stored_user = User.query.filter_by(email=data['email']).first()

        if(stored_user):
            if(pbkdf2_sha256.verify(data['password'], stored_user.password)):
                if(stored_user.token):
                    token = stored_user.token
                else:
                    token = jwt.encode({"user": {'email': stored_user.email, 'role': stored_user.role, 'id': stored_user.id}}, SECRET_KEY, algorithm='HS256')
                    stored_user.token = token
                    db.session.commit()
                return jsonify({'issue': False, 'token': token,  'message': "Login success"})
            else:
                return jsonify({'issue': True, 'message': "Invalid Password"})

        return jsonify({'issue': True, 'message': 'User not found!'})
    except Exception as e:
        return jsonify({'issue': True, 'message':str(e)})
   
    


@app.route('/register', methods=['POST'])
def registerUser():
    try:
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        
        if(user):
            return jsonify({'issue': True,  'message': "email is already present in database"})                

        hashed = pbkdf2_sha256.using(rounds=10, salt_size=16).hash(data['password'])
        new_user = User(username=data['username'],email=data['email'], password=hashed, role=data['role'], token="")
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'issue': False, 'message': 'register success'})
    except Exception as e:
        return jsonify({'issue': True, 'message':str(e)})


@app.route("/profile", methods=['PATCH', 'PUT'])
def udpateProfile():
    try:
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
        user = User.query.get(user_data['id'])
        data = request.get_json()
        if 'username' in data:
            user.username = data['username']
       

        db.session.commit()
        return jsonify({'issue': False,'message': f'user data updated successfully!'})
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/tasks", methods=['GET', 'POST'])
def getTask():
    try:
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
         
        if(request.method == "POST"):
            if(user_data['role'] == 'admin'):
                data = request.get_json()
                new_task = Task(title=data['title'], description=data['description'], due_date=data['due_date'], completed=data['completed'], user_id=user_data['id'])
                db.session.add(new_task)
                db.session.commit()
                return jsonify({'issue': False, 'message': "task added!"})
            else:
                return jsonify({'issue': True, 'message': "Access Denied!"})
        
        all_task = Task.query.all()
        output = []
        for each in all_task:
            output.append({
                'id': each.id,
                'title': each.title,
                'description': each.description,
                'due_date': each.due_date,
                'completed':each.completed,
                'user_id': each.user_id,
                'team_id': each.team_id
            })
        
        return jsonify({'issue': False, 'message': "all Task", 'task': output})
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/task/<int:id>", methods=["GET",'PUT', 'PATCH', "DELETE"])
def multiTask(id):
    try:
        task = db.session.get(Task, id)
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
        if(task):
            if(request.method == "GET"):
                new_task = {
                    'id': task.id,
                    "title": task.title,
                    "description": task.description,
                    'due_date': task.due_date,
                    'completed': task.completed,
                    "user_id": task.user_id,
                    "team_id": task.team_id
                }
                return jsonify({'issue': False, 'message': "task", 'task':new_task})
            
            if(user_data['role'] == "admin"):
                if(request.method == "DELETE"):
                    db.session.delete(task)
                    db.session.commit()
                    return jsonify({'issue':False, 'message': f"task {id} deleted!"})
                
                data = request.get_json()

                if 'title' in data:
                    task.title = data['title']
                if 'description' in data:
                    task.description = data['description']
                if 'due_date' in data:
                    task.due_date = data['due_date']
                if 'completed' in data:
                    task.completed = data['completed']
                if 'user_id' in data:
                    task.user_id = data['user_id']
                if 'team_id' in data:
                    task.team_id = data['team_id']

                db.session.commit()
                return jsonify({'issue': False, 'message': "task updated!"})
            else:
                return jsonify({'issue': True, 'message': "Access Deined!"})
        else:
            return jsonify({'issue':True, 'message': 'Task not found'}) 
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/teams", methods=['GET', "POST"])
def getTeams():
    try:
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
        
        if(request.method == "POST"):
            if(user_data['role'] == "admin"):
                data = request.get_json()
                new_team = Team(name=data['name'])
                db.session.add(new_team)
                db.session.commit()

                same_user = User.query.get(user_data['id'])
                same_user.teams.append(new_team)
                db.session.commit()
                return jsonify({'issue': False, 'message': "Team added!"}) 
            else:
                return jsonify({'issue': True, 'message': "Access Deined!"})


        all_teams = Team.query.all()
        output = []
        for each in all_teams:
            output.append({
                'id': each.id,
                'name': each.name
            })

        return jsonify({'issue':False, 'message': "all teams", "teams": output})
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})


@app.route("/team/<int:id>", methods=['GET', "PUT", "DELETE", "PATCH"])
def multiTeam(id):
    try:
        team = db.session.get(Team, id)
        token = request.headers.get('Authorization')
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_data = decoded_token['user']
        if(team):
            if(request.method == "GET"):
                new_team = {
                    'id': team.id,
                    "name": team.name,
                   
                }
                return jsonify({'issue': False, 'message': "team", 'team':new_team})
            
            if(user_data['role'] == "admin"):
                if(request.method == "DELETE"):
                    db.session.delete(team)
                    db.session.commit()
                    return jsonify({'issue':False, 'message': f"team {id} deleted!"})
                
                data = request.get_json()

                if 'name' in data:
                    team.name = data['name']
                

                db.session.commit()
                return jsonify({'issue': False, 'message': "team updated!"})
            else:
                return jsonify({'issue': True, 'message': "Access Deined!"})
        else:
            return jsonify({'issue':True, 'message': 'Team not found'}) 
    except Exception as e:
        return jsonify({'issue': True, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)