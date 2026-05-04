FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend
COPY sdk /app/sdk
COPY examples /app/examples
ENV PYTHONPATH=/app/backend:/app/sdk
ENV OPAD_DATA_DIR=/app/data
EXPOSE 1337
CMD ["uvicorn", "opad.main:app", "--host", "0.0.0.0", "--port", "1337"]
