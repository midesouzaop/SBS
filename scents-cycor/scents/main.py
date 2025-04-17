import os
import subprocess
import datetime
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
from functools import wraps
import re
import requests
from flask_mail import Mail, Message
#import datetime
#from yourapp import app, db, mail 
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
#import os




from main import db  # Referência ao seu app "main"
from main.models import LogEmail  # Ajuste conforme necessário
app = Flask(__name__)



ARQUIVO = 'usuarios_autorizados.json'

# Inicializar Flask-Mail
#mail = Mail(app)

#app = Flask(__name__)

# Criar pasta de uploads
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Verificar se o ffmpeg está instalado
def check_ffmpeg_installed():
    try:
        result = subprocess.run(['which', 'ffmpeg'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise EnvironmentError("ffmpeg não está instalado no sistema.")
        print("FFmpeg encontrado no sistema")
    except Exception as e:
        raise EnvironmentError(f"Erro ao verificar ffmpeg: {str(e)}")

check_ffmpeg_installed()

# Configurações
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
db = SQLAlchemy(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    sobrenome = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    cpf_cnpj = db.Column(db.String(20), unique=True)
    username = db.Column(db.String(80), unique=True)
    nome_fantasia = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))
    whatsapp = db.Column(db.String(20))
    pagamento_confirmado = db.Column(db.Boolean, default=False)
class GeneratedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
class LogEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    destinatario = db.Column(db.String(120))
    assunto = db.Column(db.String(255))
    status = db.Column(db.String(50))
    erro = db.Column(db.Text, nullable=True)
    data_envio = db.Column(db.DateTime, default=datetime.datetime.utcnow)
with app.app_context():
    db.drop_all()
    db.create_all()

# Funções auxiliares
import cv2
import numpy as np

def generate_video_with_audio(image_filename, mp3_filename, output_filename):
    try:
        if not os.path.exists(image_filename):
            raise Exception(f"Imagem não encontrada: {image_filename}")
        if not os.path.exists(mp3_filename):
            raise Exception(f"Áudio não encontrado: {mp3_filename}")

        img = cv2.imread(image_filename)
        if img is None:
            raise Exception("Erro ao carregar imagem")

        height, width = img.shape[:2]
        if width > 640:
            scale = 640 / width
            width = 640
            height = int(height * scale)
            img = cv2.resize(img, (width, height))

        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_filename, fourcc, 24.0, (width, height))

        # Gera 30 segundos de vídeo (24fps * 30s = 720 frames)
        for _ in range(720):
            out.write(img)

        out.release()

        # Combina vídeo e áudio usando ffmpeg
        temp_video = output_filename + '.temp.mp4'
        os.rename(output_filename, temp_video)
        os.system(f'ffmpeg -i {temp_video} -i {mp3_filename} -c:v copy -c:a aac -shortest {output_filename}')
        os.remove(temp_video)

        if not os.path.exists(output_filename):
            raise Exception("Arquivo de saída não foi gerado")

        return True
    except Exception as e:
        print(f"Erro detalhado ao gerar vídeo: {str(e)}")
        return False

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['user_id']
    except:
        return None

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Token é necessário'}), 403
        token = auth_header.split(' ')[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = db.session.get(User, data['user_id'])
        except:
            return jsonify({'message': 'Token inválido ou expirado'}), 401
        return f(current_user, *args, **kwargs)
    return decorated_function

# Rotas
@app.route('/login', methods=['GET'])
def login_page():
    return send_from_directory('.', 'login.html')


@app.route('/check_usage', methods=['GET'])
@token_required
def check_usage(current_user):
    return jsonify({
        'file_count': current_user.file_count,
        'limit': 10,
        'message': 'Uso verificado com sucesso'
    })



@app.route('/generate_video', methods=['POST'])
@limiter.limit("5 per minute")
@token_required
def generate_video(current_user):
    
    def encontrar_audio(nome_arquivo='audio_A5CBR.mp3', pasta_raiz='.'):
        for raiz, dirs, arquivos in os.walk(pasta_raiz):
            if nome_arquivo in arquivos:
                caminho_encontrado = os.path.abspath(os.path.join(raiz, nome_arquivo))
                print(f"[INFO] Áudio encontrado em: {caminho_encontrado}")
                return caminho_encontrado
        print("[ERRO] Arquivo de áudio não encontrado.")
        return None

    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    user_id = current_user.id
    key = f"user:{user_id}:requests"

    try:
        # Verificar o limite de requisições por minuto
        requests_made = redis_client.get(key)
        if requests_made and int(requests_made.decode()) >= 5:
            return jsonify({'message': 'Limite de requisições por minuto atingido'}), 429

        redis_client.incr(key)
        redis_client.expire(key, 60)

        # Procurar o arquivo de áudio
        audio_file = encontrar_audio('audio_A5CBR.mp3', pasta_raiz='.')
        if not audio_file or not os.path.exists(audio_file):
            return jsonify({'message': 'Arquivo de áudio não encontrado'}), 400

        # Procurar a última imagem gerada
        last_image = GeneratedFile.query.filter_by(user_id=user_id).order_by(GeneratedFile.timestamp.desc()).first()
        if not last_image:
            return jsonify({'message': 'Nenhuma imagem encontrada'}), 400

        image_path = os.path.join(app.config['UPLOAD_FOLDER'], last_image.filename)
        if not os.path.exists(image_path):
            print(f"[ERRO] Arquivo de imagem não encontrado: {image_path}")
            return jsonify({'message': 'Arquivo de imagem não encontrado'}), 400
        else:
            print(f"[INFO] Arquivo de imagem localizado com sucesso: {image_path}")

        # Caminho para o vídeo gerado
        video_filename = f"video_user_{user_id}_{uuid.uuid4().hex}.mp4"
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)

        # Gerar o vídeo
        sucesso = generate_video_with_audio(image_path, audio_file, video_path)
        if not sucesso or not os.path.exists(video_path):
            return jsonify({'message': 'Falha ao gerar vídeo'}), 500

        # Registrar o novo vídeo gerado
        new_file = GeneratedFile(filename=video_filename, user_id=user_id)
        current_user.file_count += 1
        db.session.add(new_file)
        db.session.commit()

        video_url = f'/video/{video_filename}'

        return jsonify({
            'message': 'Vídeo gerado com sucesso!',
            'video_url': video_url
        }), 200

    except Exception as e:
        print(f"[ERRO] {e}")
        return jsonify({'message': 'Erro ao gerar vídeo'}), 500
        
        
        
def email_valido(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None


def validar_cnpj(cnpj):
    cnpj = re.sub(r'\D', '', cnpj)
    url = f'https://brasilapi.com.br/api/cnpj/v1/{cnpj}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {'valid': True, 'message': 'CNPJ válido', 'data': data}
        elif response.status_code == 404:
            return {'valid': False, 'message': 'CNPJ não encontrado'}
        else:
            return {'valid': False, 'message': f'Erro BrasilAPI: {response.status_code}'}
    except requests.exceptions.RequestException as e:
        return {'valid': False, 'message': f'Erro na requisição: {str(e)}'}





def enviar_email(destinatario, assunto, corpo):
    try:
        smtp_host = os.getenv("SMTP_HOST", "smtp.smtp2go.com")
        smtp_port = int(os.getenv("SMTP_PORT", 2525))
        smtp_user = os.getenv("SMTP_USERNAME")
        smtp_pass = os.getenv("SMTP_PASSWORD")
        email_from = os.getenv("EMAIL_FROM")

        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = destinatario
        msg["Subject"] = assunto
        msg.attach(MIMEText(corpo, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        with open("envio_emails.log", "a") as log_file:
            log_file.write(f"[{datetime.datetime.now()}] E-mail enviado para {destinatario} | Assunto: {assunto}\n")

        log = LogEmail(destinatario=destinatario, assunto=assunto, status="Sucesso")
        db.session.add(log)
        db.session.commit()

    except Exception as e:
        erro = str(e)
        with open("envio_emails.log", "a") as log_file:
            log_file.write(f"[{datetime.datetime.now()}] ERRO ao enviar e-mail para {destinatario} | Erro: {erro}\n")

        log = LogEmail(destinatario=destinatario, assunto=assunto, status="Erro", erro=erro)
        db.session.add(log)
        db.session.commit()
@app.route('/emails_enviados', methods=['GET'])
def listar_emails_enviados():
    try:
        email = request.args.get('email')
        
        with open("usuarios_autorizados.json", "r") as arquivo:
            dados_autorizados = json.load(arquivo)

        if email not in dados_autorizados["usuarios"]:
            return jsonify({'message': 'Usuário não autorizado'}), 403

        status_filtro = request.args.get('status')

        query = LogEmail.query
        if status_filtro:
            query = query.filter_by(status=status_filtro)

        logs = query.order_by(LogEmail.data_envio.desc()).all()

        resultados = [{
            'id': log.id,
            'destinatario': log.destinatario,
            'assunto': log.assunto,
            'status': log.status,
            'erro': log.erro,
            'data_envio': log.data_envio.strftime('%Y-%m-%d %H:%M:%S')
        } for log in logs]

        return jsonify(resultados), 200

    except Exception as e:
        return jsonify({'message': f'Erro ao buscar logs de e-mails: {str(e)}'}), 500





def confirmar_pagamento_assas(pedido_id):
    url = f'https://api.assas.com.br/v1/pedidos/{pedido_id}/status'
    headers = {'Authorization': 'Bearer SEU_TOKEN_AQUI'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'PAID':
                return {'status': 'paid', 'message': 'Pagamento confirmado.'}
            else:
                return {'status': 'unpaid', 'message': 'Pagamento não confirmado.'}
        else:
            return {'status': 'error', 'message': f'Erro Assas: {response.status_code}'}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f'Erro na requisição: {str(e)}'}







@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['nome', 'sobrenome', 'email', 'cpf_cnpj', 'username', 'password', 'nome_fantasia']

        if not data or not all(field in data for field in required_fields):
            return jsonify({'message': 'Dados inválidos'}), 400

        if not email_valido(data['email']):
            return jsonify({'message': 'Formato de e-mail inválido'}), 400

        cnpj_result = validar_cnpj(data['cpf_cnpj'])
        if not cnpj_result['valid']:
            return jsonify({'message': cnpj_result['message']}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Usuário já existe'}), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email já cadastrado'}), 400
        if User.query.filter_by(cpf_cnpj=data['cpf_cnpj']).first():
            return jsonify({'message': 'CPF/CNPJ já cadastrado'}), 400

        hashed_password = generate_password_hash(data['password'])
        nome_fantasia = data.get('nome_fantasia', '') or cnpj_result['data'].get('nome_fantasia', '')

        new_user = User(
            nome=data['nome'],
            sobrenome=data['sobrenome'],
            email=data['email'],
            cpf_cnpj=data['cpf_cnpj'],
            username=data['username'],
            nome_fantasia=nome_fantasia,
            password_hash=hashed_password,
            whatsapp=data.get('whatsapp', '')
        )

        db.session.add(new_user)
        db.session.commit()

        assunto = "Bem-vindo à nossa plataforma!"
        corpo = f"""
Olá, {data['nome']}!

Seu cadastro foi realizado com sucesso.

Nome de usuário: {data['username']}
Email: {data['email']}

"""
        enviar_email(data['email'], assunto, corpo)

        return jsonify({'message': 'Usuário registrado com sucesso!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Erro ao registrar: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        token = generate_token(user.id)
        return jsonify({'message': 'Login bem-sucedido', 'token': token})
    return jsonify({'message': 'Credenciais inválidas'}), 401
import json
@app.route('/api/autorizados', methods=['POST'])
def adicionar_usuario():
    dados = request.json
    novo_usuario = {
        "nome_usuario": dados.get("nomeUsuario"),
        "email": dados.get("email"),
        "senha": dados.get("senha"),
        "nome": dados.get("nome"),
        "sobrenome": dados.get("sobrenome"),
        "razao_social": dados.get("razaoSocial"),
        "cnpj": dados.get("cnpj"),
        "aroma": dados.get("aroma")
    }

    if os.path.exists(ARQUIVO):
        with open(ARQUIVO, 'r') as f:
            usuarios = json.load(f)
    else:
        usuarios = []

    usuarios.append(novo_usuario)

    with open(ARQUIVO, 'w') as f:
        json.dump(usuarios, f, indent=4)

    return jsonify({"mensagem": "Usuário autorizado e salvo com sucesso."}), 201
@app.route('/confirmar_pagamento', methods=['POST'])
def confirmar_pagamento():
    try:
        data = request.get_json()
        pedido_id = data.get('pedido_id')
        cpf_cnpj = data.get('cpf_cnpj')

        if not pedido_id or not cpf_cnpj:
            return jsonify({'message': 'Pedido ID ou CPF/CNPJ não fornecido'}), 400

        # Verificação de autorização por e-mail
        email_usuario = data.get('email')
        try:
            with open("usuarios_autorizados.json", "r") as arquivo:
                dados_autorizados = json.load(arquivo)
            if email_usuario not in dados_autorizados["usuarios"]:
                return jsonify({'message': 'Usuário não autorizado'}), 403
        except Exception as e:
            return jsonify({'message': f'Erro ao verificar autorização: {str(e)}'}), 500

        # Caso especial para Michele
        if cpf_cnpj == '31.031.795/0001-29':
            user = User.query.filter_by(cpf_cnpj=cpf_cnpj).first()
            if not user:
                # Criação automática do usuário Michele
                user = User(
                    nome='Michele',
                    sobrenome='Salles de Souza',
                    email='michele.souza@cycor.com.br',
                    cpf_cnpj='31.031.795/0001-29',
                    username='powerful',
                    nome_fantasia='Cycor Cibernética',
                    password_hash=generate_password_hash('universo10'),
                    whatsapp='4192188569',
                    pagamento_confirmado=True
                )
                db.session.add(user)
            else:
                user.pagamento_confirmado = True

            db.session.commit()

            # Enviar e-mail para Michele
            login_url = "https://scents.onrender.com/login"
            assunto = "Acesso Liberado Gratuitamente"
            corpo = f"""
Olá, Michele!

Seu acesso à nossa API foi liberado gratuitamente conforme combinado.

Aqui estão seus dados de acesso:

Nome: Michele Salles de Souza  
Usuário: powerful  
Senha: sua senha

Acesse o sistema pelo link:
{login_url}

Se precisar de ajuda, estamos à disposição.

Atenciosamente,  
Equipe Scents
"""
            enviar_email(user.email, assunto, corpo)
            return jsonify({'message': 'Usuária Michele registrada ou atualizada e liberada. E-mail enviado.'}), 200

        # Validação do CNPJ
        cnpj_validado = validar_cnpj(cpf_cnpj)
        if not cnpj_validado['valid']:
            return jsonify({'message': cnpj_validado['message']}), 400

        # pagamento = confirmar_pagamento_assas(pedido_id)

        user = User.query.filter_by(cpf_cnpj=cpf_cnpj).first()
        if user:
            user.pagamento_confirmado = True
            db.session.commit()

            login_url = "https://scents.onrender.com/login"
            assunto = "Pagamento Confirmado"
            corpo = f"""
Olá, {user.nome}!

Seu pagamento foi confirmado com sucesso.

Aqui estão seus dados de acesso:

Nome: {user.nome} {user.sobrenome}  
Usuário: {user.username}  
Senha: {data.get('password', '***')}

Link para login:
{login_url}
"""
            enviar_email(user.email, assunto, corpo)
            return jsonify({'message': 'Pagamento confirmado e e-mail enviado.'})
        else:
            return jsonify({'message': 'Usuário não encontrado'}), 404

    except Exception as e:
        return jsonify({'message': f'Erro ao confirmar pagamento: {str(e)}'}), 500
import os
from flask import request, Response, abort

@app.route('/video/<filename>', methods=['GET'])
def serve_video(filename):
    video_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(video_path):
        print(f"Vídeo não encontrado em: {video_path}")
        return "Vídeo não encontrado", 404

    try:
        range_header = request.headers.get('Range', None)
        file_size = os.path.getsize(video_path)

        if range_header:
            # Ex: "Range: bytes=0-1023"
            byte1, byte2 = 0, None
            m = range_header.replace('bytes=', '').split('-')
            if m[0]:
                byte1 = int(m[0])
            if len(m) > 1 and m[1]:
                byte2 = int(m[1])
            else:
                byte2 = file_size - 1

            length = byte2 - byte1 + 1

            with open(video_path, 'rb') as f:
                f.seek(byte1)
                data = f.read(length)

            response = Response(data,
                                status=206,
                                mimetype='video/mp4',
                                direct_passthrough=True)
            response.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
            response.headers.add('Accept-Ranges', 'bytes')
            response.headers.add('Content-Length', str(length))
            return response

        else:
            # Sem header Range — retorna vídeo completo
            with open(video_path, 'rb') as f:
                data = f.read()

            return Response(data,
                            status=200,
                            mimetype='video/mp4',
                            direct_passthrough=True)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return str(e), 500

@app.route('/save_token', methods=['POST'])
def save_token():
    try:
        data = request.get_json()
        token = data.get('token')
        if not token:
            return jsonify({'message': 'Token não fornecido'}), 400
        return jsonify({'message': 'Token salvo com sucesso'})
    except Exception as e:
        return jsonify({'message': f'Erro ao salvar token: {str(e)}'}), 500

@app.route('/')
def index():
    return send_from_directory('.', 'login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return send_from_directory('.', 'register.html')




@app.route('/upload')
def upload_page():
    return send_from_directory('.', 'upload.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api-docs')
def api_docs():
    return send_from_directory('.', 'api-docs.html')

@app.route('/list-uploads', methods=['GET'])
@token_required
def list_uploads(current_user):
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        files.append({
            'filename': filename,
            'uploaded_at': datetime.datetime.fromtimestamp(
                os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ).isoformat()
        })
    return jsonify(files)

@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'media' not in request.files:
        return jsonify({'detail': 'Nenhum arquivo enviado'}), 400

    file = request.files['media']
    if not file or not file.filename:
        return jsonify({'detail': 'Arquivo inválido'}), 400

    # Verificar se é uma imagem ou vídeo
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
    if '.' not in file.filename or \
       file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'detail': 'Tipo de arquivo não permitido. Envie apenas imagens ou vídeos'}), 400

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    new_file = GeneratedFile(filename=filename, user_id=current_user.id)
    db.session.add(new_file)
    current_user.file_count += 1
    db.session.commit()

    try:
        db.session.commit()
        return jsonify({'message': 'Arquivo enviado com sucesso', 'filename': filename})
    except Exception as e:
        db.session.rollback()
        return jsonify({'detail': 'Erro de conexão ao fazer upload'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
