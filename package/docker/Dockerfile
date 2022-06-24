FROM nginx:latest
RUN apt-get update
RUN apt-get --assume-yes install vim
RUN apt-get --assume-yes install nginx-module-njs
COPY default.conf /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY njs.js /etc/nginx/conf.d
