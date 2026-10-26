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
| `SCHEMASPY_TIMEOUT_SECONDS` | `3600` | Limite do SchemaSpy por banco (substitui o antigo `SCHEMASPY_TIMEOUT_MIN`, que ainda é aceito) |
| `SCHEMASPY_MAX_TABLES_FULL` | `1500` | Acima desse nº de tabelas o banco roda em **modo leve**: `-degree 1 -noimplied` (diagramas só com vizinhos diretos, sem relações implícitas) |
| `SCHEMASPY_TIMEOUT_LARGE_SECONDS` | `10800` | Limite do SchemaSpy no modo leve (bancos grandes, ex.: DBSENIOR) |
| `JDBC_CONNPROPS` | `encrypt\=false;trustServerCertificate\=true` | Propriedades do driver JDBC |
| `SITE_TITLE` | `Documentação dos bancos` | Título da página |

## Segurança da senha

A senha do SQL Server nunca vai na linha de comando do SchemaSpy: ela é gravada num `schemaspy.properties` (permissão 0600) num diretório temporário apagado ao fim de cada execução (`-configFile`). Mensagens de erro, logs, `schemaspy.log`, `status.json` e o índice HTML passam por uma máscara (`-p X`, `password=X`, `Password=X`, `PWD=X` e o valor literal de `MSSQL_PASSWORD`/`SQL_CONSOLE_PASSWORD`/`BASIC_AUTH_PASSWORD` viram `***`). Ao iniciar, o `status.json` salvo no volume é regravado já mascarado.

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
Aceita **lotes com várias instruções** (separadas por `;` ou por quebra de linha), por exemplo `DECLARE @x VARCHAR(10) = '001'; SELECT … WHERE c = @x;`.
Cada instrução é validada por um analisador que ignora strings, `[identificadores]`, `"aspas"` e comentários (`--`, `/* */`):

- **Permitido:** `SELECT` (inclusive `SELECT @var = …`), `WITH … SELECT`, `DECLARE @var` (escalares e `TABLE`), `SET @var = …`,
  opções de sessão (`SET NOCOUNT`, `ANSI_*`, `ROWCOUNT`, `DATEFORMAT`, `STATISTICS`, `SHOWPLAN_*`…), `PRINT`,
  `EXEC`/`EXECUTE` só de `sp_help`, `sp_helptext`, `sp_helpindex`, `sp_helpconstraint`, `sp_columns`, `sp_tables`, `sp_pkeys`,
  `sp_fkeys`, `sp_spaceused`, `sp_who`, `sp_who2`, `sp_databases`, `sp_stored_procedures`, `sp_server_info` com argumentos literais.
- **SHOW:** SQL Server não tem `SHOW TABLES`; use `INFORMATION_SCHEMA.TABLES` ou `EXEC sp_tables`. O console traduz `SHOW TABLES`, `SHOW VIEWS`, `SHOW PROCEDURES` e `SHOW DATABASES`.
- **Bloqueado:** `INSERT`/`UPDATE`/`DELETE`/`MERGE` (inclusive em variáveis de tabela), `SELECT … INTO`, tabelas `#temp`, DDL (`CREATE`/`ALTER`/`DROP`/`TRUNCATE`),
  `GRANT`/`REVOKE`/`DENY`, `EXEC` de qualquer outro procedimento, `sp_executesql`, `xp_*`, `OPENROWSET`/`OPENQUERY`/`OPENDATASOURCE`, `BULK`,
  `BACKUP`/`RESTORE`, `DBCC`, `SHUTDOWN`, `KILL`, `USE`, `WAITFOR`, cursores, `IF`/`WHILE`/`BEGIN`, e comandos de transação. A mensagem de erro cita a instrução recusada.

O lote roda numa transação sempre desfeita, com `LOCK_TIMEOUT`, timeout e limite de linhas **por conjunto de resultado**; todos os conjuntos são exibidos
(a API devolve `result_sets` e mantém `columns`/`rows` do primeiro). Banco validado contra a lista. Cada consulta é registrada no log do container (sem credenciais).
Mesmo assim, use um login só leitura:

```sql
CREATE LOGIN dbdoc_console WITH PASSWORD = '<senha forte>';
-- em cada banco liberado:
CREATE USER dbdoc_console FOR LOGIN dbdoc_console;
ALTER ROLE db_datareader ADD MEMBER dbdoc_console;
```

Testes do validador: `python3 -m unittest discover -s tests`.

## Tamanho dos bancos

No início de cada varredura o documentador lê o tamanho de dados e de log de cada banco (`sys.master_files`; se não houver permissão,
`sys.database_files` em cada banco; se ambos falharem, mostra "—"). O total aparece na coluna **Tamanho** da página inicial (dica com dados/log)
e no seletor de banco do console. Fica salvo no `status.json`. O botão **Atualizar tamanhos** (`POST /api/sizes`) relê só os tamanhos, sem nova varredura.

## Última atividade (bancos possivelmente inativos)

Junto com o tamanho (na varredura e no botão **Atualizar tamanhos e atividade**), o documentador lê, só leitura:
última escrita e última leitura (`MAX(last_user_update)` e seek/scan/lookup de `sys.dm_db_index_usage_stats`, exige `VIEW SERVER STATE`),
início do SQL Server (`sys.dm_os_sys_info`), última mudança de estrutura (`MAX(modify_date)` de `sys.objects`, sem objetos do sistema)
e último backup completo (`msdb.dbo.backupset`, se houver leitura). Tudo fica no `status.json`; sem permissão, aparece "—".

**Atenção:** essas estatísticas zeram quando o SQL Server reinicia. "Sem escrita desde que o servidor ligou em X" quer dizer só isso.
O banco recebe o selo cinza **possivelmente inativo** quando não teve escrita desde que o servidor ligou e o servidor está ligado há mais de 30 dias,
ou quando a última escrita tem mais de 90 dias. Para habilitar: `GRANT VIEW SERVER STATE TO dbdoc;` (e, opcional, `db_datareader` em `msdb` para os backups).

## Baixar .md selecionados

Na página inicial, marque os bancos (ou "Marcar todos") e clique em **Baixar .md selecionados**. O `.zip` (`documentacao-md-AAAAMMDD.zip`) traz, por banco, os `.md` da pasta (`schema.md`, `amostras.md`), opcionalmente o `schema.json`, e um `LEIA-ME.md` pensado para entregar a uma IA. Endpoint: `GET /api/bundle?db=A&db=B[&json=1]` (com Basic auth).
