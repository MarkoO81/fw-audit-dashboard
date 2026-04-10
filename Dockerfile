FROM node:22-alpine

WORKDIR /app

# Install dependencies first (layer cache)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copy app files
COPY server.js ./
COPY index.html ./

EXPOSE 3737

CMD ["node", "server.js"]
