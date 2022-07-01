FROM frolvlad/alpine-glibc:alpine-3.5_glibc-2.24

ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /dir
COPY ./challenge /dir

# System deps
RUN apk add --update socat && apk add --update gdb &&\
    rm -rf /var/cache/apk/*