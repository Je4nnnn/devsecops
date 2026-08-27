ARG PYTHON_IMAGE=python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
FROM ${PYTHON_IMAGE} AS dependencies

# La base esta fijada por digest, asi que no recibe los parches que Alpine ya
# publico para su rama (ej. openssl 3.5.8-r0 corrige CVE-2026-14456). Este
# upgrade los aplica sin soltar el pin de la imagen base.
RUN apk upgrade --no-cache

WORKDIR /app

RUN adduser -D -H -s /sbin/nologin appuser && \
    chown appuser:appuser /app

COPY requirements.txt .
# La API usa JWT HS256; ecdsa es transitiva y no se utiliza.
RUN pip install --no-cache-dir -r requirements.txt && \
    pip uninstall --yes ecdsa && \
    rm -rf /root/.cache /tmp/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

FROM dependencies AS test
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt && \
    pip uninstall --yes ecdsa && \
    rm -rf /root/.cache /tmp/*
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser tests ./tests
USER appuser
CMD ["pytest", "tests", "--cov=app", "--cov-report=term"]

FROM dependencies AS production
COPY --chown=appuser:appuser app ./app
USER appuser
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
