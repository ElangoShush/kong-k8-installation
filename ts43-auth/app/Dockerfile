# syntax=docker/dockerfile:1.7
FROM python:3.11-slim

# --- Runtime envs (override at deploy time as needed)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    VERIFY_TLS=false \
    HTTP_TIMEOUT_SECONDS=10

# --- Create non-root user & workdir
WORKDIR /app
RUN useradd -r -u 10001 -g root appuser && chown -R appuser:root /app

# --- Copy only deps first for better layer caching
COPY requirements.txt ./
RUN pip install --upgrade --no-cache-dir pip && \
    pip install --no-cache-dir -r requirements.txt

# --- Copy the single microservice file
COPY ts43-issue-auth-code.py ./ts43-issue-auth-code.py

# --- Switch to non-root
USER appuser

# --- Expose service port
EXPOSE 8080

# --- Run ONLY this microservice
CMD ["python", "-u", "ts43-issue-auth-code.py"]
