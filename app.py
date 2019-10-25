#coding:utf-8
from flask import Flask, render_template, request, url_for, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

#app = Flask(__name__)
app = Flask("campainha-virtual-api")
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def converter_datetime(value):
    #Converte datetime object em string para processamento JSON
    if value is None:
        return None
    return [value.strftime("%Y-%m-%d"), value.strftime("%H:%M:%S")]

class Usuario(db.Model):
    __tablename__='usuario'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nome = db.Column(db.String, unique=True)
    senha_hash = db.Column(db.String)

    def __init__(self, nome, senha):
        self.nome = nome
        self.senha_hash = generate_password_hash(senha)

    @property
    def serialize(self):
        return {
            'id': self._id,
            'nome': self.nome,
            'senha_hash': self.senha_hash
        }

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
    dataehora = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String)

    def __init__(self, status):
        self.status = status

    #usar marshmallow para serialização complexas
    @property
    def serialize(self):
        return {
            '_id' : self._id,
            'dataehora': converter_datetime(self.dataehora),
            'status': self.status,
            # Exemplo de muitos para muitos
            #'many2many': self.serialize_many2many
        }

    #@property
    #def serialize_many2many(self):
    #    return [item.serialize for item in self.many2many]

class Gpio(db.Model):
    __tablename__ = 'gpio'
    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pin = db.Column(db.Integer, unique=True)
    status = db.Column(db.Integer)

    def __init__(self, pin):
        self.pin = pin
        self.status = 0

    @property
    def serialize(self):
        return {
            '_id': self._id,
            'pin': self.pin,
            'status': self.status,
        }


db.create_all()

@app.route('/', methods=['GET'])
def home():
    lista_usuario = Usuario.query.all()
    if not lista_usuario:
        json_list=[{'message': 'Acesse 127.0.0.1:5000/index e cadastre um novo usuário'}]
        return jsonify(json_list), 206
    return jsonify([usuario.serialize for usuario in lista_usuario]), 200

@app.route("/senha/<string:senha>", methods=['GET'])
def senha(senha):
    lista_usuario = Usuario.query.all()
    if not lista_usuario:
        json_list=[{'message': 'Acesse 127.0.0.1:5000/index e cadastre um novo usuário'}]
        return jsonify(json_list), 206
    json_list=[usuario.serialize for usuario in lista_usuario if check_password_hash(usuario.senha_hash, senha)]
    if not json_list:
        json_list=[{'message': 'Senha inválida!'}]
        return jsonify(json_list), 404
    json_list=[{'message': 'Usuário aceito'}]    
    return jsonify(json_list), 200

@app.route('/camera', methods=['GET'])
def listar_cameras():
    lista_cameras = Camera.query.all()
    if not lista_cameras:
        json_list=[{'message': 'Não há câmeras cadastradas'}]
        return jsonify(json_list), 206
    return jsonify([camera.serialize for camera in lista_cameras]), 200

@app.route("/camera/<string:descricao>", methods=['GET'])
def procura_camera(descricao):
    camera = Camera.query.filter_by(descricao=descricao).first()
    if not camera:
        json_list=[{'message': 'Não há câmera com essa descrição'}]
        return jsonify(json_list), 206
    json_list=[{
            '_id': camera._id,
            'ip': camera.ip,
            'descricao': camera.descricao,
        }]
    return jsonify(json_list), 200

@app.route("/notificacao/<string:status>", methods=['GET'])
def procura_notificacao(status):
    notificacao = Notificacao.query.filter_by(status=status).first()
    if not notificacao:
        json_list=[{'message': 'Não há notificacao com esse status'}]
        return jsonify(json_list), 206
    json_list=[{
            '_id': notificacao._id,
            'dataehora': notificacao.dataehora,
            'status': notificacao.status,
        }]
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
            '_id': gpio._id,
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

@app.route("/camera/<string:descricao>", methods=['PUT'])
def atualizar_camera(descricao):
    camera = Camera.query.filter_by(descricao=descricao).first()
    if not camera:
        json_list=[{'message': 'Não há câmera com essa descrição'}]
        return jsonify(json_list), 404
    camera.ip=request.get_json().get('ip')
    db.session.commit()
    return listar_cameras()

@app.route("/notificacao/<int:id>", methods=['PUT'])
def atualizar_notificacao(id):
    notificacao = Notificacao.query.filter_by(_id=id).first()
    if not notificacao:
        json_list=[{'message': 'Não há notificacao com esse id'}]
        return jsonify(json_list), 404
    notificacao.status=request.get_json().get('status')
    db.session.commit()
    return jsonify(notificacao), 200

@app.route("/gpio/<int:pin>", methods=['PUT'])
def atualizar_gpio(pin):
    gpio = Gpio.query.filter_by(pin=pin).first()
    if not gpio:
        json_list=[{'message': 'Não há gpio com esse id'}]
        return jsonify(json_list), 404
    gpio.status=request.get_json().get('status')
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

#########  fim da api rest #########

@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/cadastrar")
def cadastrar():
    return render_template("cadastro.html")

@app.route("/lista")
def lista():
    usuarios = Usuario.query.all()
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
        nome = request.form.get("nome")
        senha = request.form.get("senha")

        if nome and senha:
            u = Usuario(nome, senha)
            db.session.add(u)
            db.session.commit()
    return redirect(url_for("index"))

@app.route("/excluirUsuario/<int:id>")
def excluirUsuario(id):
    usuario = Usuario.query.filter_by(_id=id).first()
    db.session.delete(usuario)
    db.session.commit()

    return redirect(url_for("lista"))

@app.route("/atualizarUsuario/<int:id>", methods=['GET', 'POST'])
def atualizarUsuario(id):
    usuario = Usuario.query.filter_by(_id=id).first()
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")

        if nome and senha:
            usuario.nome = nome
            usuario.senha_hash = generate_password_hash(senha)

            db.session.commit()
            return redirect(url_for("lista"))

        if nome:
            usuario.nome = nome
            db.session.commit()
            return redirect(url_for("lista"))

    return render_template("atualizarUsuario.html", usuario=usuario)

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

#remover debug e use_reloader para deploy
if __name__ == "__main__":
    app.run(debug=True,  use_reloader=True)
