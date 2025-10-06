# Dockerfile - Python app with nmap installed, for Render.com Docker service
FROM python:3.11-slim

# Install system deps (nmap + minimal tools). Keep layers small and clean apt lists.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nmap \
      iproute2 \
      net-tools \
      ca-certificates \
      gcc \
      make \
 && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY . /app

# Expose port for clarity (Render will set $PORT)
EXPOSE 10000

# Some sensible environment defaults; Render will inject PORT at runtime
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Use gunicorn in production; it will bind to $PORT at runtime.
CMD ["sh", "-c", "exec gunicorn app:app --bind 0.0.0.0:${PORT} --workers 4 --threads 4"]
