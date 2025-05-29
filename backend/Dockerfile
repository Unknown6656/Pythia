FROM python:3.13-alpine AS build

RUN mkdir /app
WORKDIR /app

ARG API_PORT

EXPOSE $API_PORT

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python", "main.py"]
