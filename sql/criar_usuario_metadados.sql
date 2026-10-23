-- Usuário que enxerga SOMENTE a estrutura dos bancos (sem SELECT em tabelas).
-- Rode como sysadmin. Troque a senha.

USE master;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'doc_metadados')
    CREATE LOGIN doc_metadados WITH PASSWORD = 'TroqueEstaSenha!2026', CHECK_POLICY = ON;
GO

-- Cria o usuário em todos os bancos de usuário ONLINE e concede só metadados.
DECLARE @db sysname, @sql nvarchar(max);
DECLARE c CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.databases
    WHERE database_id > 4 AND state_desc = 'ONLINE' AND is_read_only = 0;
OPEN c;
FETCH NEXT FROM c INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'USE ' + QUOTENAME(@db) + N';
        IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ''doc_metadados'')
            CREATE USER doc_metadados FOR LOGIN doc_metadados;
        GRANT VIEW DEFINITION TO doc_metadados;
        GRANT VIEW DATABASE STATE TO doc_metadados;';
    BEGIN TRY
        EXEC sp_executesql @sql;
        PRINT 'OK: ' + @db;
    END TRY
    BEGIN CATCH
        PRINT 'FALHOU: ' + @db + ' - ' + ERROR_MESSAGE();
    END CATCH;
    FETCH NEXT FROM c INTO @db;
END
CLOSE c; DEALLOCATE c;
GO

-- Conferência: este usuário NÃO deve conseguir ler dados.
-- EXECUTE AS LOGIN = 'doc_metadados';
-- SELECT TOP 1 * FROM <algum_banco>.dbo.<alguma_tabela>;   -- deve dar erro de permissão
-- REVERT;
