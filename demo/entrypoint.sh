#!/bin/sh

set -e

. /opt/venv/bin/activate

until pg_isready -U "${DATABASE_USER}" -h "${DATABASE_HOST}" -p "${DATABASE_PORT}"
do
    echo "Postgres is unavailable - sleeping for 5 seconds"
    sleep 5
done

python manage.py migrate --noinput || exit 1
python manage.py collectstatic --noinput || exit 1

exec daphne -b 0.0.0.0 -p 8000 demo.asgi:application
