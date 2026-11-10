FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/vigilante

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
COPY docs ./docs

RUN pip install --upgrade pip \
    && pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home --home-dir /home/vigilante --shell /usr/sbin/nologin vigilante \
    && mkdir -p /data \
    && chown vigilante:vigilante /data

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

ENV DATABASE_URL=sqlite:////data/vigilante.db
