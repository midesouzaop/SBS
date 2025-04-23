from main import app, db, User, enviar_email
from werkzeug.security import generate_password_hash
import secrets
import string

def gerar_senha(tamanho=12):
    caracteres = string.ascii_letters + string.digits + "!@#$%&*"
    return ''.join(secrets.choice(caracteres) for _ in range(tamanho))

def salvar_em_log(usuario, senha):
    with open("senhas_geradas.log", "a") as f:
        f.write(f"{usuario}: {senha}\n")

def criar_usuario(nome, sobrenome, email, cpf_cnpj, username, whatsapp, nome_fantasia=None, senha=None, is_admin=False):
    senha = senha or gerar_senha()
    senha_hash = generate_password_hash(senha)

    user = User(
        nome=nome,
        sobrenome=sobrenome,
        email=email,
        cpf_cnpj=cpf_cnpj,
        username=username,
        nome_fantasia=nome_fantasia,
        whatsapp=whatsapp,
        password_hash=senha_hash,
        pagamento_confirmado=True,
        is_admin=is_admin
    )

    db.session.add(user)
    db.session.commit()

    salvar_em_log(username, senha)

    login_url = "https://scents.onrender.com/login"
    corpo_email = f"""
    Olá {nome},

    Sua conta foi criada com sucesso no sistema Scents.

    Aqui estão suas credenciais:
    Usuário: {username}
    Senha: {senha}

    Acesse o sistema através deste link:
    {login_url}

    

    Atenciosamente,
    Equipe Scents
    """
    enviar_email(email, "Sua senha de acesso ao sistema Scents", corpo_email.strip())

with app.app_context():
    db.drop_all()
    db.create_all()

    criar_usuario(
        nome="Admin",
        sobrenome="Sistema",
        email="admin@cycor.com.br",
        cpf_cnpj="00000000000000",
        username="admin",
        nome_fantasia=" Administração do Sistema",
        whatsapp="00000000000",
        senha="admin123",
        is_admin=True
    )

    criar_usuario(
        nome="Michele",
        sobrenome="Salles de Souza",
        email="michele.souza@cycor.com.br",
        cpf_cnpj="31031795000129",
        username="michele",
        nome_fantasia= "Cycor Cibernética",
        whatsapp="419218-8569"
    )

    criar_usuario(
        nome="Jenifer",
        sobrenome="Gonçalves da Silva",
        email="jenifer47silva@gmail.com",
        cpf_cnpj="45088311000192",
        username="jenny",
        nome_fantasia= "Restaurante Tempero de Família",
        whatsapp="47996257424"
    )

print("Usuários criados com sucesso. Senhas salvas e e-mails enviados.")
