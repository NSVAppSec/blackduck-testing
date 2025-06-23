# Base Image
FROM node:18 as build-stage

# Set the working directory
WORKDIR /app

# Copy dependency files
COPY package.json package-lock.json ./

# Install project dependencies
RUN npm ci

# Copy project files and folders to the current working directory
COPY . .

# Build app for production with minification
RUN npm build

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