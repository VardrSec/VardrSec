FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:47b510dd9230bf0b9bfc9b20102241e577ea7a99334ab4c3ca19f19770e9b8ea
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /acceptance
RUN npm install --no-audit --no-fund playwright@1.64.1
COPY acceptance.cjs .
COPY renewal.cjs .
COPY gate.cjs .
CMD ["node", "acceptance.cjs"]
