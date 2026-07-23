FROM python:3.12-slim

ARG BLOCKWART_BUILD_REVISION=unknown

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3
ENV BLOCKWART_BUILD_REVISION=${BLOCKWART_BUILD_REVISION}

WORKDIR /app

COPY pyproject.toml README.md ./
COPY alembic.ini ./alembic.ini
COPY docs ./docs
COPY seeds ./seeds
COPY src ./src

RUN python -m pip install --no-cache-dir .

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/api/health/ready', timeout=4).read()"

CMD ["blockwart-start"]
