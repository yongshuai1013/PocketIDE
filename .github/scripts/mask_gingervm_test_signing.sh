#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_ENV:?GITHUB_ENV must be provided by GitHub Actions}"
TEST_SIGNING_PASS=$(printf '%s' 'YW5kcm9pZA==' | base64 --decode)
printf '::add-mask::%s\n' "$TEST_SIGNING_PASS"
printf 'GINGERVM_SIGNING_PASSWORD=%s\n' "$TEST_SIGNING_PASS" >> "$GITHUB_ENV"
unset TEST_SIGNING_PASS
