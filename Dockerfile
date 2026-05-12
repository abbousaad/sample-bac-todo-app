FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production

COPY . .

RUN apk add --no-cache sqlite

EXPOSE 3000

CMD ["node", "server.js"]