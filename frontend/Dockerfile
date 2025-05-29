FROM node:alpine AS build

RUN mkdir /app
WORKDIR /app

ARG UI_PORT
ARG UI_HOST

EXPOSE $UI_PORT

ENV NODE_ENV=production
ENV PORT=$UI_PORT
ENV FORCE_COLOR=true
ENV REACT_APP_NO_CLEAR_CONSOLE=true
ENV CHOKIDAR_USEPOLLING=true
ENV WATCHPACK_POLLING=true

COPY package.json ./
RUN npm install --force

# fixing https://github.com/facebook/create-react-app/issues/2495#issuecomment-309290344 because the fucking
# react developers think that clearing the console is a great idea. what a pretentious bunch of fucking wankers.
RUN echo "'use strict';function clearConsole(){};module.exports=clearConsole;" > ./node_modules/react-dev-utils/clearConsole.js

COPY public/ ./public/
COPY src/ ./src/

CMD /bin/sh -c "ip a; PORT=$UI_PORT HOST=$UI_HOST node_modules/react-scripts/bin/react-scripts.js start --port $UI_PORT --host $UI_HOST"