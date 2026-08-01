FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 9000
# SIM_ISSUER must be the URL the BROWSER uses to reach this service (it goes into
# the token's `iss` and the discovery doc). Override per environment.
ENV SIM_ISSUER=http://localhost:9000 \
    SIM_PORT=9000

CMD ["python", "app.py"]
