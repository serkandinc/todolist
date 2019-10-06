
from flask import Flask,flash, render_template,redirect,url_for,request,session,g
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from flask_bootstrap import Bootstrap
from functools import wraps #decorators için,
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  #loginmanager için
from sqlalchemy import Integer, ForeignKey, String, Column,Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'superkey!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/LENOVO/Desktop/anka/istanbul.db'
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" 


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'))


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    todos = db.relationship('Todo',backref='user',lazy=True)
 
#flask login ile database deki guncel data arasındaki baglantı için 
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id) 

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])



@app.route('/')
def index():
    return render_template('index.html')


@app.route("/login", methods=["GET","POST"])
def login():
    form= LoginForm()
  
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:    
            if check_password_hash(user.password,form.password.data):
                login_user(user,remember=form.remember.data)
                return redirect(url_for("dashboard"))
        return '<h1>Geçersiz password veya kullanıcı</h1>'

        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template("login.html",form=form)


@app.route('/signup', methods=["GET","POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password =generate_password_hash(form.password.data,method='sha256')
        new_user=User(username=form.username.data,email=form.email.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Kaydınız başarı ile yapıldı","success")
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
    return render_template('signup.html', form=form)
  


@app.route('/dashboard')
@login_required
def dashboard():
    todos=Todo.query.filter_by(user=g.user)
    return render_template('dashboard.html',todos=todos, name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

#############################################################################
####################### Todolar3#############################################
#############################################################################
@app.route("/complete/<string:id>")
def completeTodo(id):
    todo = Todo.query.filter_by(id = id).first()
    """if todo.complete == True:
        todo.complete = False
    else:
        todo.complete = True"""
    todo.complete = not todo.complete
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.before_request
def before_request():
    g.user = current_user
	
	
@app.route("/add",methods = ["GET","POST"])
def addtodo():
    title = request.form.get("title")
    newTodo = Todo(title = title,complete = False)
    newTodo.user = g.user
    db.session.add(newTodo)
    db.session.commit()
    flash("Todo başarı ile oluşturuldu","success")
    return redirect(url_for("dashboard"))

@app.route("/delete/<string:id>")
def deleteTodo(id):
    todo = Todo.query.filter_by(id = id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("dashboard"))
 
if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()