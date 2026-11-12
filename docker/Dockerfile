# Obraz bazowy przypięty digestem indeksu multi-arch (OCI image index) tagu
# python:3.12-slim, odczytanym 2026-11-12 z registry-1.docker.io (nagłówek
# docker-content-digest). Zmiana digestu wymaga zielonego zadania CI `container`.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
# Tylko pakiet silnika (patrz .dockerignore); właściciel root, UID 65532 go nie zmieni.
COPY wpincidentlens /app/wpincidentlens
USER 65532:65532
ENTRYPOINT ["python", "-m", "wpincidentlens"]
