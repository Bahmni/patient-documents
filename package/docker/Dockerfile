FROM nginx:1.23.1-alpine


RUN apk update
RUN apk add curl acl

# Set up the apk repository for stable nginx packages
RUN printf "%s%s%s%s\n" \
    "@nginx " \
    "http://nginx.org/packages/alpine/v" \
    `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` \
    "/main" \
    | tee -a /etc/apk/repositories

# Import an official nginx signing key so apk could verify the packages authenticity
RUN curl -o /tmp/nginx_signing.rsa.pub https://nginx.org/keys/nginx_signing.rsa.pub
# Move the key to apk trusted keys storage
RUN mv /tmp/nginx_signing.rsa.pub /etc/apk/keys/
RUN apk add nginx-module-njs@nginx
COPY default.conf.template /etc/nginx/templates/
COPY nginx.conf /etc/nginx/nginx.conf
COPY njs.js /etc/nginx/conf.d

# Create Document Images Directory and modify access mode for other users
RUN mkdir -p /usr/share/nginx/html/document_images
RUN setfacl -d -m o::rx -m g::rx /usr/share/nginx/html/document_images/
