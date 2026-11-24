FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==23.0.0 cryptography==44.0.3
WORKDIR /app
COPY app.py entrypoint.sh reset_admin.py ./
COPY templates templates
COPY static static
RUN chmod +x entrypoint.sh
EXPOSE 8443
ENTRYPOINT ["./entrypoint.sh"]
