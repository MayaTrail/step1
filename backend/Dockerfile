FROM python:3.12-slim

LABEL maintainer="MayaTrail"
LABEL description="MayaTrail backend — Django + Celery"

# Prevent Python from writing .pyc files and buffer stdout/stderr.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies required by psycopg2, plus the AWS CLI v2 used by
# the playbook command runner. The v2 bundle ships its own runtime, so it does
# not affect the pinned boto3/botocore versions.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    curl \
    unzip \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in arm64) AWSARCH=aarch64 ;; *) AWSARCH=x86_64 ;; esac \
    && curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWSARCH}.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && apt-get purge -y unzip \
    && apt-get autoremove -y \
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
