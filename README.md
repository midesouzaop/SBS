
# Flask Video Generator API

Este Ã© um projeto de API em Flask que permite usuÃ¡rios autenticados fazerem upload de imagens, gerar vÃ­deos com Ã¡udio, consultar o nÃºmero de arquivos gerados e fazer o download dos vÃ­deos via streaming. A API inclui autenticaÃ§Ã£o com JWT, rate limiting com Redis e um banco de dados SQLite para persistÃªncia de usuÃ¡rios e arquivos.

## Funcionalidades

- Cadastro e autenticaÃ§Ã£o de usuÃ¡rios com JWT.
- Upload de imagem.
- Busca automÃ¡tica por arquivos de Ã¡udio.
- GeraÃ§Ã£o de vÃ­deo com imagem + Ã¡udio usando OpenCV e FFmpeg.
- Armazenamento de vÃ­deos gerados por usuÃ¡rio.
- Limite de requisiÃ§Ãµes por minuto por usuÃ¡rio com Redis.
- Streaming de vÃ­deo (suporte a `Range`).
- Log de envio de e-mails.
- ProteÃ§Ã£o contra uploads muito grandes (mÃ¡x. 16MB).

## Tecnologias

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-Limiter
- JWT (PyJWT)
- Redis
- FFmpeg
- OpenCV
- SQLite

## Requisitos

- Python 3.8+
- FFmpeg instalado e disponÃ­vel no sistema (`which ffmpeg`)
- Redis em execuÃ§Ã£o local na porta 6379

## InstalaÃ§Ã£o

1. Clone o repositÃ³rio:

```bash
git clone https://github.com/seuusuario/flask-video-generator.git
cd flask-video-generator
```

2. Crie e ative um ambiente virtual:

```bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows
```

3. Instale as dependÃªncias:

```bash
pip install -r requirements.txt
```

4. Configure a variÃ¡vel de ambiente `SECRET_KEY` (opcional):

```bash
export SECRET_KEY="sua_chave_secreta"
```

5. Execute a aplicaÃ§Ã£o:

```bash
python app.py
```

## Endpoints

### `POST /login`

Realiza login de um usuÃ¡rio.

```json
{
  "username": "seu_username",
  "password": "sua_senha"
}
```

### `GET /check_usage`

Consulta quantos arquivos o usuÃ¡rio jÃ¡ gerou (requer token JWT).

### `POST /generate_video`

Gera um vÃ­deo com a Ãºltima imagem enviada + Ã¡udio encontrado no sistema. Limite: 5 requisiÃ§Ãµes por minuto.

### `GET /video/<filename>`

Faz o streaming do vÃ­deo gerado.

## OrganizaÃ§Ã£o do projeto

- `app.py`: Arquivo principal com toda a lÃ³gica da API.
- `uploads/`: DiretÃ³rio onde imagens e vÃ­deos sÃ£o armazenados.
- `users.db`: Banco de dados SQLite com informaÃ§Ãµes de usuÃ¡rios e vÃ­deos gerados.

## SeguranÃ§a

- Todas as rotas sensÃ­veis requerem autenticaÃ§Ã£o JWT.
- Limite de upload: 16MB.
- Limite de requisiÃ§Ãµes: 5 por minuto por usuÃ¡rio.

## Autor

Jenifer - https://github.com/jeniferGoncalvesDaSilvaDev 
+5547996257424
