FROM python:3.13-alpine AS base

RUN mkdir /app
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS build

ARG API_PORT

EXPOSE $API_PORT

COPY . .
CMD fastapi run main.py --host 0.0.0.0 --port $API_PORT --workers 1 --reload
