FROM node:20-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY cloud/material_v2/package.json ./package.json
RUN npm install --omit=dev --ignore-scripts

COPY cloud/material_v2 ./cloud/material_v2
COPY tools/cloud-material ./tools/cloud-material

USER node
EXPOSE 8080
CMD ["node", "cloud/material_v2/main.mjs"]
