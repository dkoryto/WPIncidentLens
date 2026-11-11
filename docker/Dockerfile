# PoC: unpinned image; for production pin the verified image digest and create SBOM.
FROM python:3.12-slim
WORKDIR /app
COPY wptrace /app/wptrace
USER 65532:65532
ENTRYPOINT ["python", "-m", "wptrace"]
