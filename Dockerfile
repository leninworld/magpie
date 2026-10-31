FROM ghcr.io/astral-sh/uv@sha256:8d1825eb3e41b0142309f4a1c5c7781f072d8c8c9964ea073f34788a030bbeba
RUN groupadd --gid 1001 validation && useradd --uid 1001 --gid 1001 --create-home --shell /bin/sh validation
USER 1001:1001
ENV HOME=/home/validation
WORKDIR /project
