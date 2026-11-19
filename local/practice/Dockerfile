FROM python:3.12-alpine
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /code \
    && echo "public artifacts for this challenge. everything your players may inspect offline lives in /code at build time." > /code/ORIGIN.txt
EXPOSE 80
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
