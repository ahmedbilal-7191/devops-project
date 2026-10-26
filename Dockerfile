ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \ 
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -r --gid 10001 app && \
    useradd -r --uid 10001 --gid 10001 --no-create-home --shell /bin/false app

COPY --chown=app:app app/ .

USER app:app

CMD ["python", "app.py"]