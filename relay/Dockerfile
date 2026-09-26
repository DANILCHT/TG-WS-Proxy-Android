FROM python:3.12-alpine
COPY tg_ws_relay.py /app/tg_ws_relay.py
USER nobody
EXPOSE 8080
ENV RELAY_PORT=8080
ENTRYPOINT ["python3", "-u", "/app/tg_ws_relay.py"]
