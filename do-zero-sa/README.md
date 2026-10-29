# Do Zero a S.A. — plataforma em construção

Interface responsiva em estilo streaming premium, com catálogo, estúdio de criação e biblioteca de materiais.

## O que já funciona nesta versão
- Catálogo visual e navegação adaptada a celular e computador.
- Instalação como aplicativo web (PWA) em navegadores compatíveis.
- Cache da interface para abrir a estrutura básica offline após a primeira visita.
- Biblioteca local com IndexedDB: arquivos e projetos podem continuar no navegador após atualizar a página.
- Remoção individual de materiais/projetos e limpeza da biblioteca local.
- Workflow do GitHub Actions preparado para publicar a pasta no GitHub Pages.

## Limite importante da biblioteca local
Os materiais ficam **no dispositivo e no navegador usados para adicioná-los**. Eles ainda não são enviados para uma conta ou servidor e não ficam disponíveis em outros dispositivos. O espaço disponível depende do navegador e do dispositivo; vídeos grandes podem exceder a quota. Não limpe os dados do navegador enquanto precisar dos arquivos locais.

## Publicação
O workflow `.github/workflows/deploy-do-zero-sa.yml` publica a pasta `do-zero-sa` no GitHub Pages quando há alterações na branch `feat/do-zero-sa-platform`. O Pages precisa estar habilitado no repositório com a origem de publicação configurada para **GitHub Actions**. O endereço final só deve ser considerado disponível depois que a execução do workflow terminar com sucesso.

## Próximas etapas para chegar à plataforma completa
1. Backend com autenticação, upload remoto e armazenamento persistente.
2. Banco de dados para biblioteca, projetos e contas.
3. Processamento em fila: FFmpeg, transcrição com Whisper e revisão de capítulos/cortes.
4. Geração e renderização de vídeos animados, legendas e formatos horizontal/vertical.
5. Área privada do aluno, progresso e publicação de aulas.

O software pode ser aberto e de baixo custo, mas hospedagem, armazenamento e processamento de vídeos podem ter custos. A infraestrutura de produção precisa ter armazenamento persistente e limites de upload definidos.
