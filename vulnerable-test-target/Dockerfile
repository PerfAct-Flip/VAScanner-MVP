# Deliberately misconfigured target for testing the scanner's Nuclei and
# SSH-audit ("openvas") engines end-to-end. NEVER expose this beyond an
# isolated local test network — every setting here is intentionally weak.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nginx \
    sudo \
    && rm -rf /var/lib/apt/lists/*
# Deliberately NOT running `apt-get upgrade` — leaving packages stale so the
# SSH audit's "N packages have available updates" check has something real
# to find, same as it would on an actually-neglected host.

RUN mkdir -p /var/run/sshd

# --- Weak SSH config: root login + password auth + weak crypto ---
RUN { \
      echo "PermitRootLogin yes"; \
      echo "PasswordAuthentication yes"; \
      echo "Ciphers +3des-cbc,aes128-cbc"; \
      echo "MACs +hmac-md5,hmac-sha1"; \
      echo "KexAlgorithms +diffie-hellman-group1-sha1"; \
    } >> /etc/ssh/sshd_config

RUN echo 'root:toor' | chpasswd

# Test account with unrestricted passwordless sudo (used as the scan's SSH
# credential — also itself a finding, since real audits shouldn't use an
# account like this).
RUN useradd -m -s /bin/bash vulnadmin \
    && echo 'vulnadmin:vulnpass123' | chpasswd \
    && usermod -aG sudo vulnadmin \
    && echo "vulnadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/vulnadmin

# Account with no password set at all.
RUN useradd -m -s /bin/bash nopassuser && passwd -d nopassuser

# --- Exposed .git/config over the web root (nuclei: exposures/configs/git-config) ---
RUN mkdir -p /var/www/html/.git
COPY www/index.html /var/www/html/index.html
COPY www/git-config /var/www/html/.git/config

# Directory listing on top of everything else already wrong.
RUN sed -i '/location \/ {/a\        autoindex on;' /etc/nginx/sites-available/default

EXPOSE 22 80

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
