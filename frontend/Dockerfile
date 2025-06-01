FROM node:alpine AS base

RUN mkdir /app
WORKDIR /app

ENV NODE_ENV=production

COPY package.json ./
RUN npm install --force

# fixing https://github.com/facebook/create-react-app/issues/2495#issuecomment-309290344 because the fucking
# react developers think that clearing the console is a great idea. what a pretentious bunch of fucking wankers.
RUN echo "'use strict';function clearConsole(){};module.exports=clearConsole;" > ./node_modules/react-dev-utils/clearConsole.js

FROM base AS build

COPY public/ ./public/
COPY src/ ./src/

ARG REACT_APP_UI_PORT

ENV REACT_APP_UI_PORT=$REACT_APP_UI_PORT
ENV REACT_APP_NO_CLEAR_CONSOLE=true
ENV FORCE_COLOR=true
ENV CHOKIDAR_USEPOLLING=true
ENV WATCHPACK_POLLING=true

EXPOSE $REACT_APP_UI_PORT

CMD ["/bin/sh", "-c", "PORT=$REACT_APP_UI_PORT HOST=0.0.0.0 node_modules/react-scripts/bin/react-scripts.js start --port $REACT_APP_UI_PORT --host 0.0.0.0"]
