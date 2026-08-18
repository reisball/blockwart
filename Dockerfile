FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

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
