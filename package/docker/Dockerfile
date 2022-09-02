FROM nginx:1.23.1
RUN apt-get update
RUN apt-get --assume-yes install nginx-module-njs
COPY default.conf.template /etc/nginx/templates/
COPY nginx.conf /etc/nginx/nginx.conf
COPY njs.js /etc/nginx/conf.d
