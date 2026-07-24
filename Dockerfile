FROM python:3.12-slim@sha256:9d3abd9fc11d06998ccdbdd93b4dd49b5ad7d67fcbbc11c016eb0eb2c2194891

ARG BLOCKWART_BUILD_REVISION=unknown

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3
ENV BLOCKWART_BUILD_REVISION=${BLOCKWART_BUILD_REVISION}

WORKDIR /app

COPY pyproject.toml README.md ./
COPY requirements/runtime.txt ./requirements/runtime.txt
COPY alembic.ini ./alembic.ini
COPY docs ./docs
COPY seeds ./seeds
COPY src ./src

RUN python -m pip install --no-cache-dir --constraint requirements/runtime.txt .

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=8s --start-period=10s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/api/health/ready', timeout=7).read()"

CMD ["blockwart-start"]
