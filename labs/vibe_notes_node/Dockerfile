# Optional container for the notes lab (the documented default is plain `npm start`).
# Pinned base image: Node 24 (built-in node:sqlite).
FROM node:24.12-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .
ENV NOTES_PORT=18081 NOTES_DB=/data/notes.db
# Inside the container the app must listen on 0.0.0.0; compose publishes it on 127.0.0.1 ONLY.
ENV NOTES_HOST=0.0.0.0
CMD ["node", "--no-warnings", "server.js"]
