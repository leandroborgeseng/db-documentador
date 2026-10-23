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
| `RUN_EVERY_HOURS` | `168` | Intervalo entre varreduras (168 = semanal). O resultado fica no volume `/output`; ao reiniciar, só refaz se a última varredura completa tiver mais que esse intervalo. `0` = roda uma vez |
| `SAMPLE_ROWS` | `20` | Linhas de amostra por tabela gravadas em `bancos/<banco>/amostras.md` (atrás do Basic auth). `0` desliga |
| `SAMPLE_VIEWS` | `false` | Também gera amostras das views |
| `SAMPLE_MASK_REGEX` | `senha\|password\|pass\|pwd\|hash\|salt\|token\|secret\|chave\|cpf\|cnpj\|rg\|cartao\|card` | Colunas cujo nome casa (sem diferenciar maiúsculas) aparecem como `***`. Vazio desliga a máscara |
| `SAMPLE_TIMEOUT` | `30` | Timeout (s) de cada leitura de amostra |
| `SQL_CONSOLE` | `false` | Liga o Console SQL em `/sql`. Desligado, `/sql` e `/api/sql` dão 404. Exige `BASIC_AUTH_USER`/`BASIC_AUTH_PASSWORD` (senão 403) |
| `SQL_CONSOLE_USER` / `SQL_CONSOLE_PASSWORD` | (usa `MSSQL_USER`) | Login dedicado do console. **Recomendado:** login só leitura (`db_datareader`) |
| `SQL_CONSOLE_TIMEOUT` | `30` | Timeout (s) da consulta e `LOCK_TIMEOUT` |
| `SQL_CONSOLE_MAX_ROWS` | `1000` | Máximo de linhas retornadas (o resto é marcado como truncado) |
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

## Console SQL (`/sql`)

Página para testar consultas: escolha o banco, escreva a consulta e execute (Ctrl+Enter); mostra linhas, tempo, erros e exporta CSV.
Camadas de proteção: só uma instrução `SELECT`/`WITH` (comentários removidos; bloqueia `INSERT`, `UPDATE`, `DELETE`, `INTO`, `EXEC`, `sp_`/`xp_`, `OPENROWSET` etc. fora de strings);
execução dentro de transação sempre desfeita; `LOCK_TIMEOUT` e timeout; limite de linhas; banco validado contra a lista. Cada consulta é registrada no log do container (sem credenciais).
Mesmo assim, use um login só leitura:

```sql
CREATE LOGIN dbdoc_console WITH PASSWORD = '<senha forte>';
-- em cada banco liberado:
CREATE USER dbdoc_console FOR LOGIN dbdoc_console;
ALTER ROLE db_datareader ADD MEMBER dbdoc_console;
```

Testes do validador: `python3 -m unittest discover -s tests`.
