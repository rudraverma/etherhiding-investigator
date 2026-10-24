FROM node:20-bookworm-slim

WORKDIR /app
COPY package.json runner.js ./

# No dependencies to install — zero third-party code in the execution service.
# Isolation is enforced by the container (internal network, cap_drop, read_only).
USER node

EXPOSE 3021
CMD ["node", "runner.js"]
