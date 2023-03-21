FROM python:3.11-slim as base

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    postgresql-client


FROM base as poetry

WORKDIR /usr/src/app

RUN pip install poetry~=1.4.0
COPY poetry.lock pyproject.toml ./
RUN poetry export -o requirements.txt


FROM base as builder

# Requirements only needed for installing pip-packages
RUN apt-get update && \
    apt-get install -y \
    g++ \
    git \
    ssh \
    libpq-dev

COPY --from=poetry /usr/src/app/requirements.txt /tmp/requirements.txt

RUN python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install -U pip setuptools && \
    pip install -r /tmp/requirements.txt


FROM base as final

RUN mkdir -p /app

ENV HOME=/app
ENV APP_HOME=/app/web
ENV MEDIA_ROOT=${APP_HOME}/media
ENV STATIC_ROOT=${APP_HOME}/static
ENV DJANGO_SETTINGS_MODULE=open_pki.settings

ARG user=appuser
ARG group=appuser
ARG uid=1000
ARG gid=1000

RUN groupadd -g ${gid} ${group} && \
    useradd -u ${uid} -g ${group} -s /bin/sh -m ${user}

RUN mkdir $APP_HOME && \
    mkdir -p $MEDIA_ROOT && \
    mkdir -p $STATIC_ROOT

WORKDIR $APP_HOME

COPY --from=builder /opt/venv/ /opt/venv
COPY --chown=${uid}:${gid} . $APP_HOME

ENV PATH="${PATH}:/opt/venv/bin"

USER ${uid}:${gid}

CMD ["./entrypoint.sh"]
