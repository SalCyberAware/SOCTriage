# SOCTriage API image. Railway builds this file (the service's root directory
# is backend/), and anyone can build and run it themselves:
#
#   docker build -t soctriage-backend backend
#   docker run -p 8080:8080 --env-file backend/.env soctriage-backend
#
# Base: the official Python 3.11 slim image, pinned by digest so a rebuild
# cannot pick up a different image. 3.11 matches the lock's --python-version
# (requirements.txt header). Dependabot's docker entry proposes digest updates
# and holds the minor. Both stages name the same image.
#
# Pulled from Amazon's public mirror of Docker Hub's official images
# (public.ecr.aws/docker/library) rather than Docker Hub itself: Docker Hub
# refuses anonymous pulls from shared builders such as Railway's and GitHub's
# runners. The digest is the same image index Docker Hub serves, so the mirror
# can only supply that exact image or the build fails.

# ── Build stage ─────────────────────────────────────────────────────────────
FROM public.ecr.aws/docker/library/python:3.11-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# The runtime virtualenv gets the hashed lock and nothing else.
# --require-hashes refuses any file whose hash is not in the lock.
COPY requirements.txt /src/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r /src/requirements.txt \
 && /opt/venv/bin/pip check

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM public.ecr.aws/docker/library/python:3.11-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=build /opt/venv /opt/venv

# The app imports its siblings from the working directory, as
# `cd backend && uvicorn main:app` did. Startup runs the Alembic migrations
# (database.init_db), so alembic.ini and alembic/ ship with the code, and
# lockcheck.py reads requirements.txt for /health. .dockerignore lets in only
# these. Files stay owned by root, so the process cannot rewrite its own code.
#
# That also means the image cannot create the local SQLite file the app falls
# back to without DATABASE_URL. Set DATABASE_URL (Postgres, or a SQLite path in
# a writable volume) when running the image.
WORKDIR /app
COPY . .

USER 10001

# The same uvicorn command as the Procfile. A shell so ${PORT} expands
# (Railway sets it; 8080 matches the public domain's target port), and exec so
# uvicorn replaces the shell as PID 1 and receives SIGTERM, which it handles
# with a graceful shutdown. No proxy header flags are added: the rate limiter
# falls back to the socket peer when X-Real-IP is missing, so uvicorn's
# defaults stay exactly as they were.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8080'), timeout=4)"]
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port \"${PORT:-8080}\""]
