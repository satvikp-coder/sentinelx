# Pinned base image: PHP 8.5.12 on Apache (see docs/DECISIONS.md)
FROM php:8.5.12-apache
RUN mkdir -p /data/uploads && chown -R www-data:www-data /data
COPY app/ /var/www/html/
RUN rm -rf /var/www/html/uploads && ln -s /data/uploads /var/www/html/uploads && chown -R www-data:www-data /var/www/html
