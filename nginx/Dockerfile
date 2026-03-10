FROM nginx:1.27-alpine

# Install openssl for cert generation
RUN apk add --no-cache openssl curl

# Generate self-signed cert at build time (replace with real cert in production)
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=US/ST=VA/L=Arlington/O=Solvent CyberSecurity/OU=ArgusWatch/CN=arguswatch.local"

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443
