# VulnShop lab image. Build from the repository root (docker-compose.yml does this).
FROM python:3.13-slim

# Run as an unprivileged user, not root.
RUN useradd --create-home --uid 10001 lab
WORKDIR /app
COPY lab/app.py /app/app.py
COPY lab/openapi.json /app/openapi.json
USER lab

ENV PYTHONUNBUFFERED=1 PORT=8000
EXPOSE 8000

# Docker marks the container unhealthy if /health stops answering.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["python", "/app/app.py"]
