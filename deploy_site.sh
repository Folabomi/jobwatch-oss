#!/usr/bin/env bash
# Refresh https://<your-domain>/<slug> from the latest jobwatch state.
# Renders the current local state, uploads, invalidates.
set -euo pipefail

BUCKET="${JOBWATCH_BUCKET:?set JOBWATCH_BUCKET, e.g. s3://your-bucket}"
DISTRIBUTION="${JOBWATCH_DISTRIBUTION:?set JOBWATCH_DISTRIBUTION, e.g. E1234567890ABC}"
REGION="${JOBWATCH_REGION:-us-west-2}"
SLUG="${JOBWATCH_SLUG:?set JOBWATCH_SLUG, the object key the page is served at}"
cd "$(dirname "$0")"

python3 render_site.py --out site --slug "$SLUG"

aws s3 cp "site/$SLUG" "$BUCKET/$SLUG" --region "$REGION" \
  --content-type "text/html; charset=utf-8" --cache-control "public,max-age=300" --only-show-errors
aws s3 cp "site/$SLUG.js" "$BUCKET/$SLUG.js" --region "$REGION" \
  --content-type "application/javascript; charset=utf-8" --cache-control "public,max-age=300" --only-show-errors
aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION" \
  --paths "/$SLUG" "/$SLUG.js" --query 'Invalidation.Id' --output text

echo "live at https://<your-domain>/$SLUG"
