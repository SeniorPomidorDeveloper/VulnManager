#!/bin/sh
set -eu

alias_set() {
  mc alias set local "http://minio:9000" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1
}

i=0
until alias_set; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "minio не отвечает после 30 попыток" >&2
    exit 1
  fi
  sleep 1
done

mc mb --ignore-existing "local/${RAW_BUCKET_NAME}"
mc version enable "local/${RAW_BUCKET_NAME}"
