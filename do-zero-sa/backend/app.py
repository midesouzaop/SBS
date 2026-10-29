import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, session, send_from_directory
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", APP_DIR / "data")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "do_zero_sa.sqlite3"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv", ".ppt", ".pptx", ".pdf", ".doc", ".docx", ".txt"}
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024 * 1024)))
MAX_FILES_PER_REQUEST = int(os.environ.get("MAX_FILES_PER_REQUEST", "10"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", ""),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 2 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") != "0",
    SESSION_COOKIE_SAMESITE=os.environ.get("COOKIE_SAMESITE", "None"),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)

def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with connect_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY, original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
            media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, created_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, mode TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL)""")

init_db()

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify(error="Autenticação necessária."), 401
        if request.method in {"POST", "DELETE"} and request.headers.get("X-CSRF-Token") != session.get("csrf_token"):
            return jsonify(error="Token de segurança inválido. Atualize a sessão e tente novamente."), 403
        return fn(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    allowed_origin = os.environ.get("FRONTEND_ORIGIN", "").strip()
    if allowed_origin and request.headers.get("Origin", "") == allowed_origin:
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response

@app.before_request
def cors_preflight():
    if request.method == "OPTIONS":
        return ("", 204)

@app.get("/api/health")
def health():
    return jsonify(status="ok", service="do-zero-sa-api", timestamp=now_iso())

@app.post("/api/login")
def login():
    username_config = os.environ.get("ADMIN_USERNAME", "michele-souza@cycor.com.br").strip().lower()
    password_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
    if not username_config or not password_hash:
        return jsonify(error="Configure ADMIN_USERNAME e ADMIN_PASSWORD_HASH no servidor."), 503
    data = request.get_json(silent=True) or {}
    if str(data.get("username", "")).strip().lower() != username_config or not check_password_hash(password_hash, str(data.get("password", ""))):
        return jsonify(error="Usuário ou senha inválidos."), 401
    session.clear()
    session.permanent = True
    session["is_admin"] = True
    session["username"] = username_config
    session["csrf_token"] = uuid.uuid4().hex + uuid.uuid4().hex
    return jsonify(authenticated=True, username=username_config, csrfToken=session["csrf_token"])

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(authenticated=False)

@app.get("/api/session")
def get_session():
    return jsonify(authenticated=bool(session.get("is_admin")), username=session.get("username"),
                   csrfToken=session.get("csrf_token") if session.get("is_admin") else None)

@app.get("/api/assets")
@admin_required
def list_assets():
    with connect_db() as conn:
        rows = conn.execute("SELECT id, original_name, media_type, size_bytes, created_at FROM assets ORDER BY created_at DESC").fetchall()
    return jsonify(items=[dict(row) for row in rows])

@app.post("/api/assets")
@admin_required
def upload_assets():
    files = request.files.getlist("files")
    if not files:
        return jsonify(error="Selecione arquivos no campo 'files'."), 400
    if len(files) > MAX_FILES_PER_REQUEST:
        return jsonify(error=f"Envie no máximo {MAX_FILES_PER_REQUEST} arquivos por vez."), 413
    saved = []
    try:
        for file in files:
            original_name = (file.filename or "").strip()
            safe_name = secure_filename(original_name)
            suffix = Path(safe_name).suffix.lower()
            if not safe_name or suffix not in ALLOWED_EXTENSIONS:
                raise ValueError(f"Formato não permitido: {original_name or 'arquivo sem nome'}.")
            stored_name = f"{uuid.uuid4().hex}{suffix}"
            destination = UPLOAD_DIR / stored_name
            file.save(destination)
            size = destination.stat().st_size
            if size > MAX_UPLOAD_BYTES:
                destination.unlink(missing_ok=True)
                raise OverflowError(f"O arquivo {original_name} ultrapassa o limite configurado.")
            saved.append({"id":uuid.uuid4().hex,"original_name":original_name[:255],"stored_name":stored_name,
                          "media_type":file.mimetype or "application/octet-stream","size_bytes":size,"created_at":now_iso()})
        with connect_db() as conn:
            conn.executemany("INSERT INTO assets (id, original_name, stored_name, media_type, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [(x["id"],x["original_name"],x["stored_name"],x["media_type"],x["size_bytes"],x["created_at"]) for x in saved])
    except OverflowError as exc:
        for item in saved: (UPLOAD_DIR / item["stored_name"]).unlink(missing_ok=True)
        return jsonify(error=str(exc)), 413
    except ValueError as exc:
        for item in saved: (UPLOAD_DIR / item["stored_name"]).unlink(missing_ok=True)
        return jsonify(error=str(exc)), 415
    except Exception:
        for item in saved: (UPLOAD_DIR / item["stored_name"]).unlink(missing_ok=True)
        app.logger.exception("Falha ao salvar upload")
        return jsonify(error="Não foi possível salvar os arquivos. Tente novamente."), 500
    return jsonify(items=[{k:x[k] for k in ("id","original_name","media_type","size_bytes","created_at")} for x in saved]), 201

@app.delete("/api/assets/<asset_id>")
@admin_required
def delete_asset(asset_id):
    with connect_db() as conn:
        row = conn.execute("SELECT stored_name FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None: return jsonify(error="Material não encontrado."), 404
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    (UPLOAD_DIR / row["stored_name"]).unlink(missing_ok=True)
    return jsonify(deleted=True)

@app.get("/api/assets/<asset_id>/download")
@admin_required
def download_asset(asset_id):
    with connect_db() as conn:
        row = conn.execute("SELECT stored_name, original_name FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None: return jsonify(error="Material não encontrado."), 404
    return send_from_directory(UPLOAD_DIR, row["stored_name"], as_attachment=True, download_name=row["original_name"])

@app.get("/api/projects")
@admin_required
def list_projects():
    with connect_db() as conn:
        rows = conn.execute("SELECT id, name, mode, status, created_at FROM projects ORDER BY created_at DESC").fetchall()
    return jsonify(items=[dict(row) for row in rows])

@app.post("/api/projects")
@admin_required
def create_project():
    data = request.get_json(silent=True) or {}
    name = re.sub(r"\s+", " ", str(data.get("name", "Novo projeto"))).strip()[:160]
    mode = str(data.get("mode", "")).strip()[:120]
    allowed_modes = {"Aula original com capítulos e legendas","Mini vídeos animados de aproximadamente 1 minuto","Gerar aula e mini vídeos animados"}
    if not name or mode not in allowed_modes:
        return jsonify(error="Informe um nome e um formato de produção válido."), 400
    item = {"id":uuid.uuid4().hex,"name":name,"mode":mode,"status":"draft","created_at":now_iso()}
    with connect_db() as conn:
        conn.execute("INSERT INTO projects (id, name, mode, status, created_at) VALUES (?, ?, ?, ?, ?)",
                     (item["id"],item["name"],item["mode"],item["status"],item["created_at"]))
    return jsonify(item=item), 201

@app.delete("/api/projects/<project_id>")
@admin_required
def delete_project(project_id):
    with connect_db() as conn:
        result = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        if result.rowcount == 0: return jsonify(error="Projeto não encontrado."), 404
    return jsonify(deleted=True)

@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="O envio excede o limite de tamanho configurado no servidor."), 413

if __name__ == "__main__":
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("Defina SECRET_KEY antes de iniciar o servidor.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
