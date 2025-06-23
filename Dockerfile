# Base Image
FROM node:18 as build-stage

# Set the working directory
WORKDIR /app

# Copy dependency files
COPY package.json pnpm-lock.yaml ./

# Install pnpm as packet manager
RUN npm install -g pnpm@7.27.1

# Install project dependencies
RUN pnpm install --frozen-lockfile

# Copy project files and folders to the current working directory
COPY . .

# Build app for production with minification
RUN pnpm build

# Production stage
FROM node:18 as production-stage

# Set the working directory
WORKDIR /app

# Copy sources
COPY --from=build-stage /app .

# Expose connection port
EXPOSE 3000

# Run
CMD ["node", "build"]