FROM nginx:1.27-alpine AS base

RUN mkdir /app
WORKDIR /app

RUN apk update && apk add python3

FROM base AS build

RUN /bin/sh -c "[ ! -f /etc/nginx/certs/certificate.crt ] && printf '\033[91mcertificate.crt not found. please run .../proxy/create-certificates.sh on the host system before building the docker container.\033[0m\n'" || exit 1
RUN /bin/sh -c "[ ! -f /etc/nginx/certs/certificate.key ] && printf '\033[91mcertificate.key not found. please run .../proxy/create-certificates.sh on the host system before building the docker container.\033[0m\n'" || exit 1

COPY ./process-variables.py /app/
COPY ./nginx.conf /app/

CMD python3 process-variables.py /app/nginx.conf > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'
