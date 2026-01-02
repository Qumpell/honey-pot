FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -r honey && useradd -r -g honey honey
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R honey:honey /app
USER honey
EXPOSE 2222 2223

CMD ["python", "main.py"]