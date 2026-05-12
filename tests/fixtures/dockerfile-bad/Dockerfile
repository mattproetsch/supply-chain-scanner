FROM node:20
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
RUN apt-get update && apt-get install -y curl
RUN curl -sL https://example.com/install.sh | bash
COPY . .
CMD ["node", "server.js"]
