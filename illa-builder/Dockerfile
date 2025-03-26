# -------------------
# build runner images
FROM node:16-bullseye
WORKDIR /opt/illa/illa-builder-frontend
COPY .. /opt/illa/illa-builder-frontend
RUN npm install -g pnpm@8.1.0
RUN pnpm install
# RUN pnpm build-self
EXPOSE 5173 3000 4173 4174
CMD [ "pnpm", "dev:self" ]