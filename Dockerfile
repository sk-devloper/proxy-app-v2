FROM python:3.12-slim

WORKDIR /app

# System deps (for cryptography build if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY *.py ./
COPY config.yaml ./

# Runtime directories
RUN mkdir -p logs certs

EXPOSE 8888
EXPOSE 8890

# Run in headless mode by default inside Docker.
# For the TUI, run the container with: docker run -it ...
CMD ["python", "main.py"]
