FROM python:3.12-alpine

WORKDIR /app

RUN apk upgrade --no-cache && \
    apk add --no-cache libpq && \
    adduser -D -H -s /sbin/nologin appuser && \
    chown appuser:appuser /app

COPY requirements.txt .
# La API usa JWT HS256; ecdsa queda como dependencia transitiva no usada y Trivy la reporta vulnerable.
RUN pip install --no-cache-dir -r requirements.txt && \
    pip uninstall --yes ecdsa && \
    rm -rf /root/.cache /tmp/*

COPY --chown=appuser:appuser . .

USER appuser

ENV UVICORN_HOST=0.0.0.0
ENV UVICORN_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
