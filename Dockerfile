FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE.md ./
COPY app ./app
RUN python -m pip install --no-cache-dir .

RUN addgroup --system earnproxy \
    && adduser --system --ingroup earnproxy --home /app earnproxy \
    && mkdir -p /var/lib/earn-proxy \
    && chown -R earnproxy:earnproxy /app /var/lib/earn-proxy

USER earnproxy
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "60", "app:create_app()"]
