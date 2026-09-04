FROM node:24-slim

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

CMD ["npm", "run", "preview", "--", "--port", "5173"]
