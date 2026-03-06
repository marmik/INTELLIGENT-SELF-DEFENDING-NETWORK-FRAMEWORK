FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
EXPOSE 5010
CMD ["python", "-m", "src.dashboard.app", "--host", "0.0.0.0", "--port", "5010"]
