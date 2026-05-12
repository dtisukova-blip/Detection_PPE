FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV WORKER_DB=/data/worker.db
ENV YOLO_CONFIG_DIR=/tmp/Ultralytics

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch torchvision
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='Hansung-Cho/yolov8-ppe-detection', filename='best.pt'); hf_hub_download(repo_id='Hexmon/vyra-yolo-ppe-detection', filename='best.pt')"

COPY . .

RUN mkdir -p /data

EXPOSE 8010

CMD ["python", "main.py"]
