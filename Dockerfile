FROM python:3.11

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (NO nikto)
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY new4.py .

RUN chmod +x new4.py

ENTRYPOINT ["python", "new4.py"]
