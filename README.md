# db-documentador

Container que conecta numa instância SQL Server, lista todos os bancos e gera, para cada um:

- **Diagramas e navegação (SchemaSpy):** tabelas, colunas, índices, relacionamentos reais e implícitos.
- **Dicionário de dados (`schema.md` e `schema.json`):** estrutura completa em texto, ideal para mandar para uma IA montar as views.

Tudo fica numa página web interna com a situação de cada banco. **Nenhum dado das tabelas é lido**, só metadados.

## 1. Criar o usuário no SQL Server

Rode `sql/criar_usuario_metadados.sql` como sysadmin (troque a senha). Ele cria o login `doc_metadados` com `VIEW DEFINITION` e `VIEW DATABASE STATE` em todos os bancos, sem `SELECT` em tabela nenhuma.

O SQL Server precisa aceitar login SQL (modo de autenticação misto).

## 2. Subir no Coolify

1. Coloque esta pasta num repositório Git (GitHub, Gitea ou GitLab interno).
2. No Coolify: **+ New → Application**, escolha o repositório e o build pack **Docker Compose** (`docker-compose.yml`).
3. Em **Environment Variables**, preencha no mínimo:

| Variável | Exemplo | Obrigatória |
| --- | --- | --- |
| `MSSQL_HOST` | `10.0.0.10` ou `SRVSAUDE\INSTANCIA` | sim |
| `MSSQL_PORT` | `1433` | não |
| `MSSQL_USER` | `doc_metadados` | sim |
| `MSSQL_PASSWORD` | senha do login | sim |
| `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` | protege a página | recomendado |

4. Em **Domains**, aponte um domínio interno para a porta **8080** (ex. `http://docs-bancos.pmf.local:8080`). Não exponha na internet.
5. **Deploy.** Acompanhe em **Logs**; a página já mostra a fila e atualiza sozinha a cada 15 s enquanto roda.

## Variáveis opcionais

| Variável | Padrão | Para quê |
| --- | --- | --- |
| `DATABASES` | vazio (todos) | Lista fixa: `Saude,Agenda,Regulacao` |
| `EXCLUDE_DATABASES` | vazio | Bancos para pular |
| `SCHEMAS` | `all` | `all` ou lista: `dbo,sus` |
| `ROW_COUNTS` | `true` | Contagem de linhas via `sys.dm_db_partition_stats` (não lê dados) |
| `PARALLEL` | `2` | Bancos documentados ao mesmo tempo |
| `RUN_EVERY_HOURS` | `24` | Intervalo entre varreduras; `0` = roda uma vez |
| `JAVA_OPTS` | `-Xmx1g` | Memória do SchemaSpy (aumente para bancos com milhares de tabelas) |
| `JDBC_CONNPROPS` | `encrypt\=false;trustServerCertificate\=true` | Propriedades do driver JDBC |
| `SITE_TITLE` | `Documentação dos bancos` | Título da página |

## Vários servidores SQL Server

Crie uma aplicação por instância no Coolify (mesmo repositório, variáveis diferentes), ou duplique o serviço no `docker-compose.yml` com outro `MSSQL_HOST`.

## Problemas comuns

- **Erro de SSL/certificado no SchemaSpy:** mantenha o `JDBC_CONNPROPS` padrão.
- **Instância nomeada (`SERVIDOR\INSTANCIA`):** prefira o IP e a porta fixa da instância; o SQL Browser (UDP 1434) costuma estar bloqueado entre redes.
- **Banco aparece como "erro":** abra o link `log` da linha; geralmente é falta de permissão do usuário naquele banco.
- **SchemaSpy lento ou sem memória:** aumente `JAVA_OPTS` (ex. `-Xmx3g`) e reduza `PARALLEL` para `1`.

## Próximo passo

Baixe o `schema.md` dos bancos da saúde e mande para a IA junto com a especificação das views; é o material para montar os `CREATE VIEW`.
