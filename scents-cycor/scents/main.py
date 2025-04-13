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

app = Flask(__name__)

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
    nome = db.Column(db.String(80), nullable=False)
    sobrenome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cpf_cnpj = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    whatsapp = db.Column(db.String(20))
    file_count = db.Column(db.Integer, default=0)
    generated_files = db.relationship('GeneratedFile', backref='user', lazy=True)

class GeneratedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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

@app.route('/generate_video', methods=['POST'])
@limiter.limit("5 per minute")
@token_required
def generate_video(current_user):
    import redis
    import os

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
        try:
            requests_made = redis_client.get(key)
            if requests_made and int(requests_made.decode()) >= 5:
                return jsonify({'message': 'Limite de requisições por minuto atingido'}), 429

            redis_client.incr(key)
            redis_client.expire(key, 60)
        except Exception as redis_error:
            print(f"[ERRO REDIS] {redis_error}")

        audio_file = encontrar_audio('audio_A5CBR.mp3', pasta_raiz='.')

        if not audio_file or not os.path.exists(audio_file):
            return jsonify({'message': 'Arquivo de áudio não encontrado'}), 400

        last_image = GeneratedFile.query.filter_by(user_id=user_id).order_by(GeneratedFile.timestamp.desc()).first()

        if not last_image:
            return jsonify({'message': 'Nenhuma imagem encontrada'}), 400

        image_path = os.path.join(app.config['UPLOAD_FOLDER'], last_image.filename)

        if not os.path.exists(image_path):
            print(f"[ERRO] Arquivo de imagem não encontrado: {image_path}")
            return jsonify({'message': 'Arquivo de imagem não encontrado'}), 400
        else:
            print(f"[INFO] Arquivo de imagem localizado com sucesso: {image_path}")

        # Caminho completo de saída
        video_filename = f"video_user_{user_id}_{uuid.uuid4().hex}.mp4"
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)

        # Gerar vídeo com imagem + áudio
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

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['nome', 'sobrenome', 'email', 'cpf_cnpj', 'username', 'password']
        if not data or not all(field in data for field in required_fields):
            return jsonify({'message': 'Dados inválidos'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Usuário já existe'}), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email já cadastrado'}), 400
        if User.query.filter_by(cpf_cnpj=data['cpf_cnpj']).first():
            return jsonify({'message': 'CPF/CNPJ já cadastrado'}), 400

        hashed_password = generate_password_hash(data['password'])
        new_user = User(
            nome=data['nome'],
            sobrenome=data['sobrenome'],
            email=data['email'],
            cpf_cnpj=data['cpf_cnpj'],
            username=data['username'],
            password_hash=hashed_password,
            whatsapp=data.get('whatsapp', '')
        )
        db.session.add(new_user)
        db.session.commit()

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
