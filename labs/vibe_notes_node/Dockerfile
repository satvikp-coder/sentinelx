# Optional container for the notes lab (the documented default is plain `npm start`).
# Pinned base image: Node 24 (built-in node:sqlite).
FROM node:24.12-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .
ENV NOTES_PORT=18081 NOTES_DB=/data/notes.db
# NOTE: the app binds 127.0.0.1 inside the container; for Docker publishing set NOTES_HOST (see compose).
CMD ["node", "--no-warnings", "server.js"]
