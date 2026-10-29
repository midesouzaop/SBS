# Do Zero a S.A. — plataforma em construção

A plataforma está organizada em três frentes:

- **Área pública** (index.html): apresentação e catálogo de conteúdos. Os itens exclusivos são identificados como conteúdo para membros.
- **Entrada de membros** (login.html) e **página de assinatura** (membros.html): estrutura visual pronta, aguardando integração de autenticação de assinantes, cadastro, provedor de pagamento e confirmação automática da assinatura.
- **Área administrativa** (admin.html): login administrativo por e-mail/usuário autorizado, biblioteca remota, upload de materiais, download e exclusão, além de cadastro de projetos — quando a API segura estiver hospedada e configurada.

## O que já existe no repositório

- Frontend responsivo, com navegação pública separada da área administrativa.
- Biblioteca local anterior, baseada em IndexedDB, no app.js.
- API Flask inicial em backend/app.py, com sessão administrativa, proteção CSRF, upload autenticado, download protegido, exclusão de materiais e projetos.
- Testes automatizados da API em backend/test_app.py.
- Estrutura de PWA e validação contínua via GitHub Actions.

## O que ainda NÃO está ativo

- O login de membros e a criação de contas de assinantes.
- Pagamento recorrente, checkout e webhook de confirmação/cancelamento.
- Regras de acesso que liberam vídeos exclusivos apenas para assinantes com pagamento válido.
- Cadastro/publicação de vídeos reais no catálogo público e ferramenta administrativa para marcar um conteúdo como público ou exclusivo.
- Transcrição, capítulos automáticos, geração de cortes, animação e renderização de vídeo.

A página de membros deixa essa condição explícita. Não há cobrança nem promessa de acesso pago ativa nesta versão.

## Configuração do backend administrativo

A API precisa ser hospedada em ambiente com HTTPS e volume persistente. Configure no servidor:

- SECRET_KEY: segredo aleatório longo para assinar sessões.
- ADMIN_USERNAME: use o e-mail da conta administrativa autorizada.
- ADMIN_PASSWORD_HASH: hash Werkzeug da senha, nunca a senha em texto puro.
- DATA_DIR: diretório persistente para banco de dados e arquivos.
- FRONTEND_ORIGIN: origem exata do frontend autorizada para chamadas com credenciais.
- COOKIE_SECURE=1 em HTTPS.
- Opcional: MAX_UPLOAD_BYTES, MAX_FILES_PER_REQUEST e PORT.

A URL da API deve ser definida em config.js por meio de window.DO_ZERO_SA_API_URL. Não coloque segredos do servidor no frontend nem em arquivos do GitHub.

## Segurança e publicação

O GitHub Pages hospeda apenas arquivos estáticos: não é um backend e não deve guardar vídeos privados. O upload administrativo usa a API e os arquivos precisam permanecer fora da pasta pública do site. Para conteúdo de membros, a validação de assinatura e a autorização de reprodução/download devem ocorrer no servidor, nunca apenas por um bloqueio visual na página.

Antes de abrir assinaturas, é necessário escolher e configurar o provedor de pagamento, implementar os webhooks verificados e os estados de assinatura, completar a API de membros e testar a autorização de cada conteúdo. O processamento de vídeo também exigirá infraestrutura própria e pode gerar custos de armazenamento e computação.
