# PHISH-X hosted (cloud) version: lite model, static sandbox only, privacy-safe.
FROM python:3.12-slim
WORKDIR /app
COPY requirements-hosted.txt .
RUN pip install --no-cache-dir -r requirements-hosted.txt
COPY src ./src
COPY models/xgboost.joblib models/email_text.joblib ./models/
COPY reports ./reports
ENV PHISHX_HOSTED=1 PHISHX_LITE=1 PHISHX_SANDBOX_MODE=static PHISHX_HOST=0.0.0.0 PORT=8765
EXPOSE 8765
WORKDIR /app/src
CMD ["python", "server.py"]
