FROM alpine:3.20

ARG CLI_NAME="networkscan"
ARG TARGETPLATFORM
ARG NMAP_VERSION="7.95-r0"

# nmap is a dependency for multiple commands
# libpcap is a direct runtime dependency of the SYN scanner, not just nmap's.
RUN apk update && apk --no-cache add ca-certificates bash git libpcap nmap=$NMAP_VERSION nmap-scripts=$NMAP_VERSION sudo

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/ && \
  mkdir -p /opt/method/${CLI_NAME}/var/data && \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output

COPY $TARGETPLATFORM/${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

# Make nmap be able to run as a sudoer without password prompt
RUN \
  adduser --disabled-password --gecos '' method && \
  echo "method ALL=(ALL) NOPASSWD: /usr/bin/nmap" > /etc/sudoers.d/method && \
  echo "method ALL=(ALL) NOPASSWD: /opt/method/networkscan/service/bin/networkscan" >> /etc/sudoers.d/method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output && \
  chmod 757 /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
ENTRYPOINT [ "sudo", "networkscan" ]
