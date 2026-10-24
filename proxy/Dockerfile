FROM mitmproxy/mitmproxy:11.1.3

# addon + launcher
COPY addon.py /addon/addon.py
COPY entrypoint.sh /usr/local/bin/etherhawk-entrypoint.sh

USER root
RUN chmod +x /usr/local/bin/etherhawk-entrypoint.sh

EXPOSE 8095 8081

ENTRYPOINT ["/usr/local/bin/etherhawk-entrypoint.sh"]
