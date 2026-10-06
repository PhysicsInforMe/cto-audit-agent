FROM python:3.12-slim

LABEL maintainer="CTO Audit Agent"
LABEL description="Audit your codebase like a CTO — containerized"

# Installa git (necessario per sorgenti remote)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Crea utente non-root
RUN useradd -m -s /bin/bash auditor

# Copia e installa il tool
WORKDIR /app
COPY . /app/

RUN pip install --no-cache-dir -e ".[ui]"

# Switch a utente non-root
USER auditor

# Porta per la dashboard (se usata)
EXPOSE 8050

# Default: agent mode (headless audit)
ENTRYPOINT ["cto-audit"]
CMD ["--help"]
