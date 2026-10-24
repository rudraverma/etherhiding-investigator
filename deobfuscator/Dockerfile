FROM node:20-bookworm-slim

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./

# Run as the image's built-in non-root user.
USER node

EXPOSE 3020
CMD ["node", "server.js"]
