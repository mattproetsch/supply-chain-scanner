FROM node:24-alpine@sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f AS base
WORKDIR /app

FROM base AS deps
RUN echo "install"

FROM base AS build
COPY . .

# Lower-case `as` and mixed-case stage name — Docker is case-insensitive here.
FROM Base as Runtime
COPY --from=build /app /app

# Not a stage reference — must still flag DOCKER_NO_TAG.
FROM unknown-image
