FROM python:3.12-slim

WORKDIR /app

# System deps (psutil may need gcc on some arches, but slim usually fine)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netmonitor ./netmonitor
COPY pyproject.toml .
COPY README.md .

# Config and runtime volumes
VOLUME ["/root/.netmonitor", "/data"]

# Default: run interactive CLI. Override with: netmonitor daemon start
ENTRYPOINT ["netmonitor"]
CMD ["run"]
