FROM python:3.12-slim

# whois for recon; gosu to drop privileges; ca-certificates for TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
      whois ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 etherhawk

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh /usr/local/bin/etherhawk-api-entrypoint.sh
RUN chmod +x /usr/local/bin/etherhawk-api-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/etherhawk-api-entrypoint.sh"]
