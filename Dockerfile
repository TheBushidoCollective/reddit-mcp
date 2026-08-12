# Two stages, so the compiler and the dev dependencies never reach the running
# image. The build stage needs TypeScript, vitest and the rest of the toolchain;
# what Cloud Run starts needs dist and the production dependency tree, nothing
# else.
FROM node:22-slim AS build

WORKDIR /app

# The manifest and lockfile come first on their own so that editing a source file
# does not invalidate the install layer, which is the slow one.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Pruned in place rather than resolved again in a separate stage. Same result as a
# second `npm ci --omit=dev`, one install instead of two, and it is provably the
# same tree the build just compiled against rather than a fresh resolution that
# could differ.
RUN npm prune --omit=dev

FROM node:22-slim

# express and the SDK both branch on this, and the default is development, which
# turns on stack traces in responses among other things.
ENV NODE_ENV=production

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist

# The manifest ships because "type": "module" lives in it. Without it Node reads
# the compiled output as CommonJS and the process dies on the first import.
COPY package.json ./

# node:22-slim already ships an unprivileged `node` user. Root buys nothing here:
# the process reads its configuration from the environment and writes nothing to
# disk.
USER node

# Nothing is baked in. Every credential arrives as an environment variable that
# Cloud Run populates from Secret Manager when an instance starts, so an image
# pulled out of Artifact Registry is worth nothing on its own.
CMD ["node", "dist/http-entry.js"]
