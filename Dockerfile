FROM python:3.12.4-slim-bookworm
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "certificate-forger.py"]
