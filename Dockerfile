# ==========================================
# STAGE 1: Build the React application
# ==========================================
FROM node:18-alpine AS build

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your application code
COPY . .

# Build the project (Vite outputs the production files to a 'dist' folder)
RUN npm run build


# ==========================================
# STAGE 2: Serve the app with Nginx web server
# ==========================================
FROM nginx:alpine

# Copy the built production assets from Stage 1 into Nginx
COPY --from=build /app/dist /usr/share/nginx/html

# Expose port 80 so the container can receive web traffic
EXPOSE 80

# Start the Nginx server
CMD ["nginx", "-g", "daemon off;"]