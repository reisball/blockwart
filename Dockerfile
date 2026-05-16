FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3

WORKDIR /app

COPY pyproject.toml README.md ./
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY docs ./docs
COPY seeds ./seeds
COPY src ./src

RUN python -m pip install --no-cache-dir .

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "blockwart.main:app", "--host", "0.0.0.0", "--port", "8000"]
