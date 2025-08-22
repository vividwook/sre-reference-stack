FROM python:3.11-slim
WORKDIR /app
COPY app.py /app/
RUN pip install --no-cache-dir flask prometheus_client gunicorn
EXPOSE 8080
CMD ["gunicorn","-b","0.0.0.0:8080","app:app"]
