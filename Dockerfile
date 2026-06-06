FROM docker.io/library/python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies and create the flaresolverr user.
# camoufox ships its own Firefox build (fetched below), so we no longer install
# Chromium/chromedriver. We keep xvfb so the browser can run behind a virtual
# display (recommended for Cloudflare), plus the usual helper tools.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        xvfb dumb-init procps curl vim xauth \
    && rm -rf /var/lib/apt/lists/* \
    # Create flaresolverr user
    && useradd --home-dir /app --shell /bin/sh flaresolverr \
    && chown -R flaresolverr:flaresolverr . \
    # Create config dir
    && mkdir /config \
    && chown flaresolverr:flaresolverr /config

VOLUME /config

# Install Python dependencies (camoufox pulls in playwright), then install
# Firefox's system library dependencies via Playwright.
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && python -m playwright install-deps firefox \
    # Remove temporary files
    && rm -rf /var/lib/apt/lists/* /root/.cache

USER flaresolverr

# Download the camoufox Firefox build into the flaresolverr user's cache so it
# is baked into the image (avoids a large download on first run).
RUN python -m camoufox fetch

COPY src .
COPY package.json ../

EXPOSE 8191
EXPOSE 8192

# dumb-init avoids zombie browser processes
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/usr/local/bin/python", "-u", "/app/flaresolverr.py"]

# Local build
# docker build -t ngosang/flaresolverr:3.5.0 .
# docker run -p 8191:8191 ngosang/flaresolverr:3.5.0

# Multi-arch build
# NOTE: camoufox only publishes Firefox builds for a subset of platforms
# (linux/amd64 and linux/arm64). The legacy linux/386 and linux/arm/v7 targets
# are no longer supported by this image.
# docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# docker buildx create --use
# docker buildx build -t ngosang/flaresolverr:3.5.0 --platform linux/amd64,linux/arm64/v8 .
#   add --push to publish in DockerHub
