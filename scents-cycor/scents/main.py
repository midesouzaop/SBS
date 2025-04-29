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
import redis
import requests 
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
app = Flask(__name__)
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
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
#app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
#app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
db = SQLAlchemy(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    sobrenome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cpf_cnpj = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    whatsapp = db.Column(db.String(20))
    file_count = db.Column(db.Integer, default=0)
    nome_fantasia = db.Column(db.String(120))
    generated_files = db.relationship('GeneratedFile', backref='user', lazy=True)

class GeneratedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#from datetime import datetime

class LogEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    destinatario = db.Column(db.String(120), nullable=False)
    assunto = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    erro = db.Column(db.Text, nullable=True)
    data_envio = db.Column(db.DateTime, default=datetime.datetime.utcnow)
with app.app_context():
    db.drop_all()
    db.create_all()

#import os
#import subprocess


def get_audio_duration(audio_path):
    with contextlib.closing(wave.open(audio_path, 'r')) as f:
        frames = f.getnframes()
        rate = f.getframerate()
        duration = frames / float(rate)
        return duration

#def generate_video_with_audio(input_path, audio_path, output_path):


def get_audio_duration(audio_path):
    with contextlib.closing(wave.open(audio_path, 'r')) as f:
        frames = f.getnframes()
        rate = f.getframerate()
        duration = frames / float(rate)
        return duration

#def generate_video_with_audio(input_path, audio_path, output_path):

import cv2
from PIL import Image
#import uuid
import numpy as np

def generate_video_with_audio(input_path, audio_path, output_path):
    try:
        if not os.path.exists(input_path):
            raise Exception(f"Arquivo de entrada não encontrado: {input_path}")
        if not os.path.exists(audio_path):
            raise Exception(f"Arquivo de áudio não encontrado: {audio_path}")

        # Detecta o tipo de arquivo
        ext = os.path.splitext(input_path)[-1].lower()
        is_image = ext in ['.jpg', '.jpeg', '.png', '.bmp']
        is_gif = ext == '.gif'
        is_video = ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm']

        temp_video = output_path + '.temp.mp4'

        if is_image:
            # Se for imagem estática
            img = cv2.imread(input_path)
            if img is None:
                raise Exception("Erro ao carregar imagem")

            height, width = img.shape[:2]
            if width > 640:
                scale = 640 / width
                width = 640
                height = int(height * scale)
                img = cv2.resize(img, (width, height))

            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(temp_video, fourcc, 24.0, (width, height))

            for _ in range(720):  # 30 segundos a 24 fps
                out.write(img)

            out.release()
            cv2.destroyAllWindows()

        elif is_gif:
            # Se for GIF animado
            clip_duration = get_audio_duration(audio_path)  # Duraçao do áudio em segundos
            os.system(f'ffmpeg -y -i "{input_path}" -t {clip_duration} -vf "scale=640:-2,fps=24" "{temp_video}"')

        elif is_video:
            # Se já for vídeo
            os.system(f'cp "{input_path}" "{temp_video}"')  # Se for Windows, pode precisar de shutil.copy

        else:
            raise Exception(f"Tipo de arquivo não suportado: {ext}")

        # Agora combina vídeo e áudio
        command = [
            'ffmpeg', '-y', '-i', temp_video, '-i', audio_path,
            '-c:v', 'copy', '-c:a', 'aac', '-shortest', output_path
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            raise Exception(f"Erro no ffmpeg: {result.stderr.decode()}")

        os.remove(temp_video)

        if not os.path.exists(output_path):
            raise Exception("Arquivo de saída não gerado")

        return True

    except Exception as e:
        print(f"Erro: {str(e)}")
        return False

def get_audio_duration(audio_path):
    try:
        import wave
        import contextlib
        import subprocess

        # Tenta pegar duração usando ffprobe (melhor)
        result = subprocess.run(
            ['ffprobe', '-v', 'error', '-show_entries',
             'format=duration', '-of',
             'default=noprint_wrappers=1:nokey=1', audio_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        duration = float(result.stdout)
        return duration
    except Exception as e:
        print(f"Erro ao pegar duração do áudio: {str(e)}")
        return 30.0  # fallback para 30s se der erro

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

@app.route('/check_usage', methods=['GET'])
@token_required
def check_usage(current_user):
    return jsonify({
        'file_count': current_user.file_count,
        'limit': 10,
        'message': 'Uso verificado com sucesso'
    })

import os
import os

def find_file_anywhere(filename):
    """
    Procura um arquivo em qualquer pasta do sistema e retorna o caminho completo
    do arquivo se encontrado. Caso contrário, retorna None.
    """
    for root, dirs, files in os.walk('/'):  # A partir da raiz do sistema
        if filename in files:
            return os.path.join(root, filename)
    return None


@app.route('/generate_video', methods=['POST'])
@limiter.limit("5 per minute")
@token_required
def generate_video(current_user):
    user_id = current_user.id
    key = f"user:{user_id}:requests"

    try:
        # Checagem de limite com Redis
        try:
            requests_made = redis_client.get(key)
            if requests_made and int(requests_made.decode()) >= 5:
                return jsonify({'message': 'Limite de requisições por minuto atingido'}), 429

            redis_client.incr(key)
            redis_client.expire(key, 60)
        except Exception as redis_error:
            print(f"[ERRO REDIS] {redis_error}")  # Pode logar no Sentry, Rollbar, etc.
            # Continua o fluxo mesmo se o Redis falhar

        # Procurar o arquivo de áudio 'audio_A5CBR.mp3' em qualquer pasta
        audio_file = find_file_anywhere('audio_A5CBR.mp3')

        if not audio_file:
            print("[ERRO] Áudio não encontrado em qualquer diretório.")
            return jsonify({'message': 'Arquivo de áudio não encontrado'}), 400

        # Pega a última imagem gerada
        last_image = GeneratedFile.query.filter_by(user_id=user_id).order_by(GeneratedFile.timestamp.desc()).first()

        if not last_image:
            return jsonify({'message': 'Nenhuma imagem encontrada'}), 400

        image_path = os.path.join(app.config['UPLOAD_FOLDER'], last_image.filename)

        # Verifica se a imagem existe
        if not os.path.exists(image_path):
            print(f"[ERRO] Imagem não encontrada: {image_path}")
            return jsonify({'message': 'Arquivo de imagem não encontrado'}), 400

        output_filename = f'video_{uuid.uuid4().hex}.mp4'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Tenta gerar o vídeo com áudio
        success = generate_video_with_audio(image_path, audio_file, output_path)

        if not success:
            return jsonify({'message': 'Erro ao gerar vídeo'}), 500

        # Salva o vídeo gerado no banco de dados
        new_video = GeneratedFile(filename=output_filename, user_id=user_id)
        db.session.add(new_video)
        db.session.commit()

        return jsonify({'message': 'Vídeo gerado com sucesso', 'video_url': f'/video/{output_filename}'}), 200
    except Exception as e:
        print(f"[ERRO GERAL] {e}")
        return jsonify({'message': 'Erro interno no servidor', 'error': str(e)}), 500


#import os

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




def email_valido(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None


def validar_cnpj(cnpj):
    cnpj = re.sub(r'\D', '', cnpj)

    if not cnpj or len(cnpj) != 14:
        return {'valid': False, 'message': 'CNPJ inválido'}

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
@app.route('/validar-cnpj', methods=['POST'])
def validar_cnpj_route():
    data = request.get_json()
    cnpj = data.get('cnpj')
    result = validar_cnpj(cnpj)
    return jsonify(result)

def enviar_email(destinatario, assunto, corpo):
    try:
        smtp_host = "smtp.smtp2go.com"
        smtp_port = 2525
        smtp_username = "cycor.com.br"
        smtp_password = "xiXeIAK35MAuWebT"
        email_from = "Scents API <michele.souza@cycor.com.br>"

        msg = MIMEMultipart()
        msg['From'] = email_from
        msg['To'] = destinatario
        msg['Subject'] = assunto
        msg.attach(MIMEText(corpo, 'plain'))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        log = LogEmail(destinatario=destinatario, assunto=assunto, status="Sucesso", erro=None)
        db.session.add(log)
        db.session.commit()
        print(f"E-mail enviado com sucesso para {destinatario}")

    except Exception as e:
        erro = str(e)
        log = LogEmail(destinatario=destinatario, assunto=assunto, status="Erro", erro=erro)
        db.session.add(log)
        db.session.commit()
        print(f"Erro ao enviar e-mail: {erro}")


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['nome', 'sobrenome', 'email', 'cpf_cnpj', 'username', 'password', 'nome_fantasia']

        if not data or not all(field in data for field in required_fields):
            return jsonify({'message': 'Dados inválidos'}), 400

        if not email_valido(data['email']):
            return jsonify({'message': 'Formato de e-mail inválido'}), 400

        # Chamada correta à função auxiliar
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

        assunto = " Bem vindo a SCENTESIA - Tecnologia Scents by Sounds"
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

#from flask import Flask, request, jsonify
#from werkzeug.utils import secure_filename
#import os
#import moviepy.editor as mp  # para checar duração dos vídeos
#from flask import Flask, request, jsonify
#from werkzeug.utils import secure_filename
#import os

#app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = 'uploads'  # ajuste conforme seu diretório

#from flask import Flask, request, jsonify
#from werkzeug.utils import secure_filename
#import os

#app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = 'uploads'  # ajuste conforme seu diretório

@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'media' not in request.files:
        return jsonify({'detail': 'Nenhum arquivo enviado'}), 400

    file = request.files['media']
    if not file or not file.filename:
        return jsonify({'detail': 'Arquivo inválido'}), 400

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}

    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'detail': 'Tipo de arquivo não permitido. Envie imagens, vídeos ou GIFs'}), 400

    # (Removemos a verificação de tamanho mínimo!)

    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    try:
        new_file = GeneratedFile(filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        current_user.file_count += 1
        db.session.commit()
        return jsonify({'message': 'Arquivo enviado com sucesso', 'filename': filename})
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao salvar no banco: {e}")
        return jsonify({'detail': 'Erro interno ao fazer upload'}), 500
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
