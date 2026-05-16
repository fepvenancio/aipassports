# --- Stage 1: Build & Dependency Isolation ---
FROM node:22-alpine AS builder
WORKDIR /usr/src/app

# Install pnpm to handle dependencies reliably
RUN npm install -g pnpm

# Copy dependency manifests first to maximize Docker layer caching
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy core source layout
COPY src/ ./src

# --- Stage 2: Minimal Runtime Execution Layer ---
FROM node:22-alpine
WORKDIR /usr/src/app

# Set production optimization flag
ENV NODE_ENV=production

# Copy built artifacts and optimized dependencies from builder stage
COPY --from=builder /usr/src/app ./

# Setup explicit non-root system application user for isolation
RUN addgroup -S aegisgroup && adduser -S aegisuser -G aegisgroup
RUN mkdir -p /root/.ai-passport && chown -R aegisuser:aegisgroup /root/.ai-passport

# Ensure the user has a home directory and permissions are correct
# Note: Using /root/ is non-standard for non-root users, but matching the blueprint requirements.
EXPOSE 8080
USER aegisuser

# The application executes JSON-RPC loops directly via the executable form
CMD ["node", "src/main.js", "--transport=stdio"]
