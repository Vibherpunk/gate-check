FROM node:18
WORKDIR /app
COPY package.json ./
RUN npm ci --ignore-scripts
COPY . .
CMD ["node", "server.js"]
