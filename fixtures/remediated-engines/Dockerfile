FROM node:20.11.5
WORKDIR /app
COPY package.json ./
RUN npm ci --ignore-scripts
COPY . .
CMD ["node", "server.js"]
