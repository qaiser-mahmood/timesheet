FROM mcr.microsoft.com/playwright:v1.45.0-jammy

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy application files
COPY . .

# Expose HTTP port for health checks and webhooks
EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["node", "server.js"]
