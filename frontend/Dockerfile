FROM node:alpine AS base

RUN mkdir /app
WORKDIR /app

ENV NODE_ENV=production
ENV REACT_APP_NO_CLEAR_CONSOLE=true

COPY package.json ./
RUN npm install --force

# fixing https://github.com/facebook/create-react-app/issues/2495#issuecomment-309290344 because the fucking
# react developers think that clearing the console is a great idea. what a pretentious bunch of fucking wankers.
RUN echo "'use strict';function clearConsole(){};module.exports=clearConsole;" > ./node_modules/react-dev-utils/clearConsole.js

FROM base AS build

COPY public/ ./public/
COPY src/ ./src/

ARG UI_PORT
ARG UI_HOST
ARG API_PORT
ARG API_HOST

EXPOSE $UI_PORT

ENV API_HOST=$API_HOST
ENV API_PORT=$API_PORT
ENV PORT=$UI_PORT
ENV FORCE_COLOR=true
ENV CHOKIDAR_USEPOLLING=true
ENV WATCHPACK_POLLING=true

CMD /bin/sh -c "ip a; PORT=$UI_PORT HOST=$UI_HOST API_HOST=$API_HOST API_PORT=$API_PORT node_modules/react-scripts/bin/react-scripts.js start --port $UI_PORT --host $UI_HOST"