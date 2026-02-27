FROM python:3.12-slim

LABEL maintainer="MayaTrail"
LABEL description="MayaTrail backend — Django + Celery"

# Prevent Python from writing .pyc files and buffer stdout/stderr.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies required by psycopg2.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cache layer).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
COPY . .

# Collect static files (admin CSS etc.) into staticfiles/.
RUN python manage.py collectstatic --noinput --settings=config.settings.prod || true

EXPOSE 8000

# Gunicorn is used in all environments; the worker container overrides CMD.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
