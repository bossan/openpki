FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    postgresql-client && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/cache/debconf/*

FROM base AS builder

# Requirements only needed for installing pip-packages
RUN apt-get update && \
    apt-get install -y \
    git

COPY ./requirements.txt requirements.txt

RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir -U pip setuptools && \
    pip install --no-cache-dir -r requirements.txt


FROM base AS final

RUN mkdir -p /app

ENV HOME=/app
ENV APP_HOME=/app/web
ENV MEDIA_ROOT=${APP_HOME}/media
ENV STATIC_ROOT=${APP_HOME}/static
ENV DJANGO_SETTINGS_MODULE=demo.settings

RUN mkdir $APP_HOME && \
    mkdir -p $MEDIA_ROOT && \
    mkdir -p $STATIC_ROOT

WORKDIR $APP_HOME

COPY --from=builder /opt/venv/ /opt/venv
COPY . $APP_HOME

ENV PATH="${PATH}:/opt/venv/bin"

CMD ["./entrypoint.sh"]
