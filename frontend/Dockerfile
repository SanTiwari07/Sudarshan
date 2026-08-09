FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
# npm ci installs exactly what package-lock.json pins - reproducible, unlike
# `npm install`, which can resolve different versions from the same commit.
RUN npm ci

COPY . .

CMD ["npm", "run", "dev", "--", "--host"]
