FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_INDEX_URL=https://mirror-pypi.runflare.com/simple/

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client \
        sshpass \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/logs /app/images

EXPOSE 5000

CMD ["python", "app.py"]
