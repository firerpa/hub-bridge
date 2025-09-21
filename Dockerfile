FROM --platform=linux/amd64 debian:bookworm-slim AS builder
LABEL maintainer="rev1si0n <lamda.devel@gmail.com>"

COPY . /service

# Change repo to ustc
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources

RUN apt update && apt install -y supervisor python3 python3-pip redis-server curl
RUN pip3 install -r service/requirements.txt --break-system-packages -i https://mirrors.ustc.edu.cn/pypi/simple
RUN mkdir -p /data

# stage 2
FROM scratch

ENV PYTHONPATH="/service:${PYTHONPATH}"
ENV PATH="/service:/service/binaries:${PATH}"

WORKDIR                 /service

COPY --from=builder / /
CMD [ "start.sh" ]