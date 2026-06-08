FROM python:3.12-slim

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY requirements.txt .
# La API usa JWT HS256; ecdsa queda como dependencia transitiva no usada y Trivy la reporta vulnerable.
RUN pip install --no-cache-dir -r requirements.txt && \
    pip uninstall --yes ecdsa

COPY --chown=appuser:appuser . .

USER appuser

ENV UVICORN_HOST=0.0.0.0
ENV UVICORN_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
