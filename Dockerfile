FROM node:22-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ nlohmann-json3-dev && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@10.4.1 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
COPY patches ./patches
RUN pnpm install --frozen-lockfile
COPY . .
ARG VITE_NETGUARD_API_URL=""
ARG VITE_APP_ID=""
ARG VITE_OAUTH_PORTAL_URL=""
ENV VITE_NETGUARD_API_URL=$VITE_NETGUARD_API_URL VITE_APP_ID=$VITE_APP_ID VITE_OAUTH_PORTAL_URL=$VITE_OAUTH_PORTAL_URL
RUN cmake -S engine -B engine/build -DCMAKE_BUILD_TYPE=Release && cmake --build engine/build -j2 && ctest --test-dir engine/build --output-on-failure
RUN pnpm check && pnpm test
RUN NODE_ENV=production pnpm build

FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=3000 NETGUARD_BINARY=/usr/local/bin/netguard
WORKDIR /app
# The scaffold's bundled server imports Vite at module load, so retain its dependencies.
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build /app/engine/build/netguard /usr/local/bin/netguard
USER node
EXPOSE 3000
CMD ["node", "dist/index.js"]
