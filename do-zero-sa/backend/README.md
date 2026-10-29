# API da Do Zero a S.A.

Backend inicial para upload autenticado, biblioteca remota e cadastro de projetos. É separado da API de vídeo que já existe na raiz do repositório.

## Endpoints
- `GET /api/health` — verificação de disponibilidade.
- `POST /api/login`, `POST /api/logout`, `GET /api/session` — sessão administrativa.
- `GET/POST /api/assets` — lista e envia materiais.
- `GET /api/assets/<id>/download`, `DELETE /api/assets/<id>` — download e remoção.
- `GET/POST /api/projects`, `DELETE /api/projects/<id>` — projetos.

O upload usa o campo multipart `files`. Tipos permitidos: vídeos comuns, PowerPoint, PDF, Word e TXT. O limite padrão é 2 GB por arquivo e 10 arquivos por envio.

## Variáveis de ambiente
- `SECRET_KEY`: segredo aleatório longo para assinar sessões.
- `ADMIN_USERNAME`: e-mail da conta administrativa autorizada. Se não definido, o padrão é `michele-souza@cycor.com.br`; em produção, mantenha esse endereço como o único usuário permitido.
- `ADMIN_PASSWORD_HASH`: hash Werkzeug da senha, nunca a senha em texto puro.
- `DATA_DIR`: diretório persistente para banco e arquivos.
- `FRONTEND_ORIGIN`: origem exata autorizada para chamadas do navegador.
- `COOKIE_SECURE=1` para HTTPS (padrão); em desenvolvimento HTTP use `COOKIE_SECURE=0`.
- Opcional: `MAX_UPLOAD_BYTES`, `MAX_FILES_PER_REQUEST`, `PORT`.

Gere um hash de senha no ambiente confiável do servidor:
```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Senha administrativa: ')))"
```

## Execução local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ADMIN_USERNAME="michele-souza@cycor.com.br"
export ADMIN_PASSWORD_HASH="$(python -c 'from werkzeug.security import generate_password_hash; print(generate_password_hash(input()))')"
export COOKIE_SECURE=0
python app.py
```

Em produção, use HTTPS, um volume persistente montado em `DATA_DIR`, backups e uma origem CORS restrita. O backend está preparado, mas ainda precisa ser hospedado, testado no ambiente de destino e conectado ao frontend. A hospedagem e o armazenamento persistente podem ter custo.
