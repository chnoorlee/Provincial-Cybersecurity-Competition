FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=65532:65532 pyproject.toml LICENSE README.md ./
COPY --chown=65532:65532 xunan ./xunan
COPY --chown=65532:65532 web ./web
RUN mkdir -p /app/data && chown 65532:65532 /app/data

USER 65532:65532
EXPOSE 8765
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=2).read()"]
CMD ["python", "-m", "xunan", "--host", "0.0.0.0", "--port", "8765", "--data-dir", "/app/data"]

