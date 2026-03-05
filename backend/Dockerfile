FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl postgresql-client && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN sed -i 's/\r$//' /app/entrypoint.sh
RUN mkdir -p /app/reports
RUN chmod +x /app/entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
