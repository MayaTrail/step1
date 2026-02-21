FROM pulumi/pulumi-python:3.207.0

WORKDIR /app

# Install Python dependencies first (cache-friendly layer ordering)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Pulumi project configuration
COPY Pulumi.yaml .

# Copy application source
COPY __main__.py .
COPY simulations/ ./simulations/

# Copy and set entrypoint
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Default environment variables (can be overridden at runtime)
# especially this state bucket name (should be separate for each user)
ENV ACTION=preview
ENV STACK=dev-default
ENV STATE_BUCKET=mayatrail-pulumi-state 
ENV AWS_REGION=ap-south-1

ENTRYPOINT ["./entrypoint.sh"]
