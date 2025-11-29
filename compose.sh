#!/bin/bash

DB_TYPE=${DB_TYPE}

echo "Using DB_TYPE=$DB_TYPE"

if [ "$DB_TYPE" = "postgres" ]; then
    DB_FILE="docker-compose.postgres.yml"
elif [ "$DB_TYPE" = "mongo" ]; then
    DB_FILE="docker-compose.mongo.yml"
elif [ "$DB_TYPE" = "fake" ]; then
    docker compose -f docker-compose.yml "$@"
    exit 1
else
    echo "Unknown DB_TYPE: $DB_TYPE"
    exit 1
fi

docker compose -f docker-compose.yml -f $DB_FILE "$@"
