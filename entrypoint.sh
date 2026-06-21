#!/bin/sh
set -e

echo "Waiting for postgres..."
until python -c "
import psycopg, os, sys
try:
    psycopg.connect(
        dbname=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT', 5432),
    ).close()
    sys.exit(0)
except Exception:
    sys.exit(1)
"; do
  sleep 1
done

echo "Postgres is up — running migrations..."
python manage.py migrate --noinput

echo "Starting Django..."
exec python manage.py runserver 0.0.0.0:8000
