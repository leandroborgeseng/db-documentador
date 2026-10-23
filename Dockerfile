FROM eclipse-temurin:17-jre-jammy

ARG SCHEMASPY_VERSION=6.2.4
ARG MSSQL_JDBC_VERSION=12.8.1.jre11

RUN apt-get update \
 && apt-get install -y --no-install-recommends graphviz fonts-dejavu-core python3 python3-pip curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/schemaspy /drivers \
 && curl -fsSL -o /opt/schemaspy/schemaspy.jar \
      "https://github.com/schemaspy/schemaspy/releases/download/v${SCHEMASPY_VERSION}/schemaspy-${SCHEMASPY_VERSION}.jar" \
 && curl -fsSL -o /drivers/mssql-jdbc.jar \
      "https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/${MSSQL_JDBC_VERSION}/mssql-jdbc-${MSSQL_JDBC_VERSION}.jar"

RUN pip3 install --no-cache-dir "pymssql>=2.3"

COPY app/ /app/

ENV OUTPUT_DIR=/output \
    PORT=8080 \
    PYTHONUNBUFFERED=1

VOLUME ["/output"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -fs http://localhost:${PORT:-8080}/health || exit 1

CMD ["python3", "/app/run.py"]
