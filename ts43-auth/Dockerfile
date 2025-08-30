# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCRIPT_PATH=/app/ts43-issue-auth-code.py

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --upgrade pip
RUN python -m pip install -r requirements.txt

# copy your uploaded script + wrapper
COPY ts43-issue-auth-code.py /app/ts43-issue-auth-code.py
COPY app/main.py /app/main.py

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
