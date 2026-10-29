FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd --create-home --uid 10001 appuser && mkdir -p /data/uploads && chown -R appuser:appuser /data
USER appuser
ENV DATA_DIR=/data PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "gunicorn --workers 2 --threads 4 --timeout 3600 --bind 0.0.0.0:$PORT app:app"]
