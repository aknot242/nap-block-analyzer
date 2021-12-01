# For Ubuntu 20.04:
FROM ubuntu:focal

# Download certificate and key from the customer portal (https://my.f5.com)
# and copy to the build context:
COPY nginx-repo.crt nginx-repo.key /etc/ssl/nginx/

# Install prerequisite packages:
RUN apt-get update && apt-get install -y apt-transport-https lsb-release ca-certificates wget gnupg2

# Download and add the NGINX signing key:
RUN wget https://cs.nginx.com/static/keys/nginx_signing.key && apt-key add nginx_signing.key

# Add NGINX Plus repository:
RUN printf "deb https://pkgs.nginx.com/plus/ubuntu `lsb_release -cs` nginx-plus\n" | tee /etc/apt/sources.list.d/nginx-plus.list

# Add NGINX App-protect repository:
RUN printf "deb https://pkgs.nginx.com/app-protect/ubuntu `lsb_release -cs` nginx-plus\n" | tee /etc/apt/sources.list.d/nginx-app-protect.list

# Download and add the NGINX Security updates signing key:
RUN wget https://cs.nginx.com/static/keys/app-protect-security-updates.key && apt-key add app-protect-security-updates.key

# Add NGINX Security Updates repository:
RUN printf "deb https://pkgs.nginx.com/app-protect-security-updates/ubuntu/ `lsb_release -cs` nginx-plus\n" | tee /etc/apt/sources.list.d/app-protect-security-updates.list

# Download the apt configuration to `/etc/apt/apt.conf.d`:
RUN wget -P /etc/apt/apt.conf.d https://cs.nginx.com/static/files/90pkgs-nginx

# Update the repository and install the most recent version of the NGINX App Protect WAF package (which includes NGINX Plus):
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y app-protect app-protect-attack-signatures app-protect-threat-campaigns

# Remove nginx repository key/cert from docker
RUN rm -rf /etc/ssl/nginx

# Forward request logs to Docker log collector:
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# Copy configuration files:
COPY nginx.conf /etc/nginx/
COPY log-policy.json waf-policy.json /etc/app_protect/conf/
COPY entrypoint.sh  /root/

CMD ["sh", "/root/entrypoint.sh"]
