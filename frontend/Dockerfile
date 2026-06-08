FROM node:24-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

# Copiamos el código fuente
COPY . .

# Definimos que esperamos una variable llamada VITE_API_URL
ARG VITE_API_URL
# La convertimos en variable de entorno para que Vite la vea durante el build
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build
# ------------------------------

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN apk upgrade --no-cache && \
    apk add --no-cache libcap && \
    setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx && \
    rm -rf /usr/share/nginx/html/* && \
    chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx /run
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

USER nginx

EXPOSE 80
