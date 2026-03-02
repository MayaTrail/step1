FROM pulumi/pulumi-python:3.207.0

WORKDIR /app

# Install Python dependencies first (cache-friendly layer ordering)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Pulumi project configuration
COPY Pulumi.yaml .

# Copy application source
COPY __main__.py .
COPY runner.py .
COPY simulations/ ./simulations/

# Default environment variables (can be overridden at runtime)
# The runner reads these as fallbacks when CLI flags are not provided.
# PULUMI_CONFIG_PASSPHRASE - add your pulumi passphrase
ENV ACTION=preview
ENV STACK=dev-default
ENV STATE_BUCKET=mayatrail-pulumi-state
ENV AWS_REGION=ap-south-1
ENV PULUMI_CONFIG_PASSPHRASE=enter-your-passphrase-here

ENTRYPOINT ["python", "runner.py"]