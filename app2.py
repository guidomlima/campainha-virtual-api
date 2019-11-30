# coding:utf-8
from flask import Flask, render_template, request, url_for,\
    redirect, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
# from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash,\
    check_password_hash
from functools import wraps
import datetime, uuid, jwt, subprocess
import urllib.request

app = Flask("campainha-virtual-api")
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'campainha-secret'

db = SQLAlchemy(app)


def converter_datetime(value):
    # Converte datetime object em string para processamento JSON
    if value is None:
        return None
    return [value.strftime("%Y-%m-%d"), value.strftime("%H:%M:%S")]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

    @property
    def serialize(self):
        return {
            'username' : self.username,
            'password': self.password,
            'admin': self.admin,
        }


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'}), 401

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify(output)


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'}), 401

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify(user_data)


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'}), 401

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def upgrade_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'}), 401

    data = request.get_json()
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    user.admin = data['admin']
    user.password = generate_password_hash(data['password'],method='sha256')
    db.session.commit()
    return jsonify({'message': 'The user has been updated'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'}), 401

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user has been deleted'})


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow()+
                                   datetime.timedelta(minutes=30)
                            }, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/login/<token>', methods=['GET'])
def current_user(token):
    if not token:
        return jsonify({'message': 'Token not found'}), 401
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
        current_user = User.query.filter_by(public_id=data['public_id']).first()
    except:
        return jsonify({'message': 'Token is invalid'}), 401
    user_data = {}
    user_data['username'] = current_user.username
    user_data['admin'] = current_user.admin
    return jsonify(user_data)


class Camera(db.Model):
    __tablename__ = 'camera'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, unique=True)
    descricao = db.Column(db.String, unique=True)

    def __init__(self, ip, descricao):
        self.ip = ip
        self.descricao = descricao

    @property
    def serialize(self):
        return {
            'id': self._id,
            'ip': self.ip,
            'descricao': self.descricao
        }


class Notificacao(db.Model):
    __tablename__ = 'notificacao'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dataehora = db.Column(db.DateTime, default=datetime.datetime.now)
    status = db.Column(db.String)

    def __init__(self, status):
        self.status = status

    @property
    def serialize(self):
        return {
            'id' : self._id,
            'dataehora': converter_datetime(self.dataehora),
            'status': self.status,
        }


class Gpio(db.Model):
    __tablename__ = 'gpio'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pin = db.Column(db.Integer, unique=True)
    status = db.Column(db.Integer)

    def __init__(self, pin, status):
        self.pin = pin
        self.status = status

    @property
    def serialize(self):
        return {
            'id': self._id,
            'pin': self.pin,
            'status': self.status,
        }

class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    remember_me = BooleanField("remember_me")

def inicializar():
    db.create_all()
    userTeste = User.query.filter_by(username='admin').first()
    if not userTeste:
        hashed_password = generate_password_hash('admin', method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), username='admin', password=hashed_password, admin=True)
        db.session.add(new_user)
        db.session.commit()

    gpioTeste = Gpio.query.filter_by(pin=18).first()
    if not gpioTeste:
        new_gpio = Gpio(18)
        db.session.add(new_gpio)
        db.session.commit()

    notificacaoTeste = Notificacao.query.first()
    if not notificacaoTeste:
        new_notificacao = Notificacao("encerrada")
        db.session.add(new_notificacao)
        db.session.commit()


inicializar()


@token_required
@app.route('/camera', methods=['GET'])
def listar_cameras():
    lista_cameras = Camera.query.all()
    if not lista_cameras:
        json_list=[{'message': 'Não há câmeras cadastradas'}]
        return jsonify(json_list), 206
    return jsonify([camera.serialize for camera in lista_cameras]), 200

# não está em uso
@app.route("/camera/<string:descricao>", methods=['GET'])
def procura_camera(descricao):
    camera = Camera.query.filter_by(descricao=descricao).first()
    if not camera:
        json_list=[{'message': 'Não há câmera com essa descrição'}]
        return jsonify(json_list), 206
    json_list=[{
            'id': camera._id,
            'ip': camera.ip,
            'descricao': camera.descricao,
        }]
    return jsonify(json_list), 200


@app.route("/notificacao/<string:status>", methods=['GET'])
def procura_notificacao(status):
    notificacao = Notificacao.query.filter_by(status=status).order_by(Notificacao._id.desc()).first()
    if not notificacao:
        json_list=[{'message': 'Não há notificacao com esse status'}]
        return jsonify(json_list), 206
    json_list={
            'id': notificacao._id,
            'dataehora': notificacao.dataehora,
            'status': notificacao.status,
        }
    return jsonify(json_list), 200


@app.route('/gpio', methods=['GET'])
def listar_gpio():
    lista_gpio = Gpio.query.all()
    if not lista_gpio:
        json_list=[{'message': 'Não há gpio cadastrado'}]
        return jsonify(json_list), 206
    return jsonify([gpio.serialize for gpio in lista_gpio]), 200


@app.route("/gpio/<int:pin>", methods=['GET'])
def procura_gpio(pin):
    gpio = Gpio.query.filter_by(pin=pin).first()
    if not gpio:
        json_list=[{'message': 'GPIO não encontrado'}]
        return jsonify(json_list), 206
    json_list=[{
            'id': gpio._id,
            'pin': gpio.pin,
            'status': gpio.status,
        }]
    return jsonify(json_list), 200


@app.route("/camera", methods=['POST'])
def cadastrar_camera():
    data = request.get_json()
    camera = Camera(**data)
    db.session.add(camera)
    db.session.commit()
    return data, 201


@app.route("/notificacao", methods=['POST'])
def cadastrar_notificacao():
    data = request.get_json()
    notificacao = Notificacao(**data)
    db.session.add(notificacao)
    db.session.commit()
    return data, 201


@app.route("/camera/", methods=['PUT'])
def atualizar_camera(descricao):
    data = request.get_json()
    jCamera = Camera(**data)
    camera = Camera.query.filter_by(descricao=jCamera.descricao).first()
    if not camera:
        json_list=[{'message': 'Não há câmera com essa descrição'}]
        return jsonify(json_list), 404
    camera.ip=jCamera.ip
    db.session.commit()
    json_list=[{'message': 'Atualizado com sucesso'}]
    return jsonify(json_list), 200


@app.route("/notificacao/<string:status>", methods=['PUT'])
def atualizar_notificacao(status):
    data = request.get_json()
    jNotificacao = Notificacao(**data)
    notificacao = Notificacao.query.filter_by(status=status).order_by(Notificacao._id.desc()).first()
    if not notificacao:
        json_list=[{'message': 'Não há notificação criada'}]
        return jsonify(json_list), 404
    notificacao.status=jNotificacao.status
    notificacao.dataehora=datetime.datetime.now()
    db.session.commit()
    json_list=[{
            'dataehora': notificacao.dataehora,
            'status': notificacao.status,
        }]
    return jsonify(json_list), 200


@app.route("/gpio/<int:pin>", methods=['PUT'])
def atualizar_gpio(pin):
    data = request.get_json()
    jGpio = Gpio(**data)
    gpio = Gpio.query.filter_by(pin=pin).first()
    if not gpio:
        json_list=[{'message': 'Não há gpio com esse id'}]
        return jsonify(json_list), 404
    gpio.status=jGpio.status
    db.session.commit()
    return jsonify(gpio), 200


@app.route("/camera/<int:id>", methods=['DELETE'])
def remover_camera(id):
    camera = Camera.query.filter_by(_id=id).first()
    if not camera:
        json_list=[{'message': 'Não há câmera com esse id'}]
        return jsonify(json_list), 404
    db.session.delete(camera)
    db.session.commit()
    return jsonify({'message': 'Câmera removida'}), 200

#  -------fim da api rest------ #


@app.route("/index")
def index():
    return render_template("index.html")


@app.route("/cadastrar")
def cadastrar():
    return render_template("cadastro.html")


@app.route("/lista")
def lista():
    usuarios = User.query.all()
    cameras = Camera.query.all()
    notificacoes = Notificacao.query.all()
    gpios = Gpio.query.all()
    return render_template("lista.html", usuarios=usuarios,
                           cameras=cameras,
                           notificacoes=notificacoes,
                           gpios=gpios)


@app.route("/cadastroUsuario",methods=['GET', 'POST'])
def cadastroUsuario():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            hashed_password = generate_password_hash(password,method='sha256')
            new_user = User(public_id=str(uuid.uuid4()), username=username, password=hashed_password, admin=False)
            db.session.add(new_user)
            db.session.commit()
    return redirect(url_for("index"))


@app.route("/cadastroCamera",methods=['GET', 'POST'])
def cadastroCamera():
    if request.method == "POST":
        ip = request.form.get("ip")
        descricao = request.form.get("descricao")

        if ip and descricao:
            c = Camera(ip, descricao)
            db.session.add(c)
            db.session.commit()
    return redirect(url_for("index"))


@app.route("/excluirCamera/<int:id>")
def excluirCamera(id):
    camera = Camera.query.filter_by(_id=id).first()
    db.session.delete(camera)
    db.session.commit()
    return redirect(url_for("lista"))


@app.route("/atualizarCamera/<int:id>", methods=['GET', 'POST'])
def atualizarCamera(id):
    camera = Camera.query.filter_by(_id=id).first()
    if request.method == "POST":
        ip = request.form.get("ip")
        descricao = request.form.get("descricao")

        if ip and descricao:
            camera.ip = ip
            camera.descricao = descricao

            db.session.commit()
            return redirect(url_for("lista"))

    return render_template("atualizarCamera.html", camera=camera)


@app.route("/cadastroNotificacao",methods=['GET', 'POST'])
def cadastroNotificacao():
    if request.method == "POST":
        status = request.form.get("status")

        if status:
            n = Notificacao(status)
            db.session.add(n)
            db.session.commit()
    return redirect(url_for("index"))


@app.route("/excluirNotificacao/<int:id>")
def excluirNotificacao(id):
    notificacao = Notificacao.query.filter_by(_id=id).first()
    db.session.delete(notificacao)
    db.session.commit()

    return redirect(url_for("lista"))


@app.route("/atualizarNotificacao/<int:id>", methods=['GET', 'POST'])
def atualizarNotificacao(id):
    notificacao = Notificacao.query.filter_by(_id=id).first()
    if request.method == "POST":
        status = request.form.get("status")

        if status:
            notificacao.dataehora=datetime.datetime.now()
            notificacao.status=status
            db.session.commit()
            return redirect(url_for("lista"))
    return render_template("atualizarNotificacao.html", notificacao=notificacao)


@app.route("/cadastroGpio",methods=['GET', 'POST'])
def cadastroGpio():
    if request.method == "POST":
        pin = request.form.get("pin")

        if pin:
            g = Gpio(pin)
            db.session.add(g)
            db.session.commit()
    return redirect(url_for("index"))


@app.route("/excluirGpio/<int:id>")
def excluirGpio(id):
    gpio = Gpio.query.filter_by(_id=id).first()
    db.session.delete(gpio)
    db.session.commit()

    return redirect(url_for("lista"))


@app.route("/atualizarGpio/<int:id>", methods=['GET', 'POST'])
def atualizarGpio(id):
    gpio = Gpio.query.filter_by(_id=id).first()
    if request.method == "POST":
        status = request.form.get("status")

        if status:
            gpio.status = status
            db.session.commit()
            return redirect(url_for("lista"))

    return render_template("atualizarGpio.html", gpio=gpio)

@app.route("/logar", methods=['GET', 'POST'])
def logar():
    form = LoginForm()
    if form.validate_on_submit():
        pass
    return render_template("login.html",form=form)

@app.route("/resetar")
def resetar():
    return render_template("resetar.html")


@app.route("/resetarForm", methods=['GET', 'POST'])
def resetarForm():
    userTeste = User.query.filter_by(username="admin").first()
    if userTeste:
        if request.method == "POST":
            validar = check_password_hash(userTeste.password,request.form.get("password"))
            if validar:
                db.drop_all()
                inicializar()
                return redirect(url_for("index"))
    return redirect(url_for("lista"))


@app.route("/imagem", methods=['GET', 'POST'])
def baixarImagem():
    # "rtsp://admin:guilima13@192.168.0.108:8800/live/ch00_0"
    endereco="rtsp://192.168.0.101/"
    if endereco.startswith('rtsp://'):
        bashCommand = "ffmpeg -i {0} -f image2 /home/guilherme/campainha/campainha-virtual-api/media/temp.jpg -y".format(endereco)
        subprocess.call(bashCommand,shell=True)
    else:
        # endereco = 'http://192.168.0.107:8080/shot.jpg'
        with urllib.request.urlopen(endereco) as url:
            with open('media/temp.jpg','wb') as f:
                f.write(url.read())
    return send_from_directory('media/', 'temp.jpg')


# remover debug e use_reloader para deploy
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True,  use_reloader=True)
