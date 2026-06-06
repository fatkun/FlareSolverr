# Multi-stage build to reduce final image size
FROM docker.io/library/python:3.11-slim-bookworm AS builder

WORKDIR /app

# Install Python dependencies in builder stage
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

# Final stage
FROM docker.io/library/python:3.11-slim-bookworm

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /app/deps /usr/local/lib/python3.11/site-packages/

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

# Install Firefox's system library dependencies via Playwright.
RUN python -m playwright install-deps firefox \
    # Remove temporary files and optimize size
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/* \
    # Remove hardware decoding libraries (from old Dockerfile optimization)
    && rm -f /usr/lib/x86_64-linux-gnu/libmfxhw* \
    && rm -f /usr/lib/x86_64-linux-gnu/mfx/* \
    # Remove unnecessary fonts and icons to save space
    && rm -rf /usr/share/icons/Adwaita \
    && rm -rf /usr/share/fonts/truetype/noto

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

# When HEADLESS=false, run with xvfb-run to provide a virtual display
# xvfb-run creates display :99, dimensions 1920x1080x24
CMD ["sh", "-c", "if [ \"$HEADLESS\" = 'false' ]; then xvfb-run -s '-screen 0 1920x1080x24' /usr/local/bin/python -u /app/flaresolverr.py; else /usr/local/bin/python -u /app/flaresolverr.py; fi"]

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
