FROM alpine:3.20
RUN apk add --no-cache tor su-exec
COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
EXPOSE 9050
ENTRYPOINT ["/entrypoint.sh"]
