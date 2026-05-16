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

# Create data directory at /home/aegisuser/.ai-passport accessible by non-root user
RUN mkdir -p /home/aegisuser/.ai-passport && chown -R aegisuser:aegisgroup /home/aegisuser/.ai-passport

EXPOSE 8080
USER aegisuser

# The application executes JSON-RPC loops directly via the executable form
CMD ["node", "src/main.js", "--transport=stdio"]