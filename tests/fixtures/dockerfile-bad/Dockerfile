FROM node:20
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
RUN apt-get update && apt-get install -y curl
RUN curl -sL https://example.com/install.sh | bash
COPY . .
CMD ["node", "server.js"]

# Mutable tag → HIGH severity branch.
FROM ubuntu:latest

# Scratch base — must short-circuit, no finding.
FROM scratch

# FROM with only a --platform flag and no image → empty parts, return.
FROM --platform=linux/arm64

# ADD with an http URL → DOCKERFILE_ADD_URL.
ADD https://example.com/script.sh /tmp/

# RUN with a strict install (npm ci with lockfile) → no INSTALL_NOT_STRICT.
RUN npm ci

# Line-continuation handling: split across multiple physical lines.
RUN apt-get update \
    && apt-get install -y \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Trailing continuation at EOF → exercises the post-loop flush branch.
RUN echo "trailing-continuation" \
