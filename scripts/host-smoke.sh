#!/usr/bin/env bash
# These are macOS host compiler checks, NOT an embedded iOS compiler test.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/main.c" <<'C'
#include <stdio.h>
int main(void) { puts("C host OK"); return 0; }
C
xcrun clang -Wall -Wextra -Werror "$work/main.c" -o "$work/c-demo"
test "$("$work/c-demo")" = 'C host OK'
cat > "$work/Greeting.swift" <<'SWIFT'
func greeting() -> String { "Swift host OK" }
SWIFT
cat > "$work/main.swift" <<'SWIFT'
print(greeting())
SWIFT
xcrun swiftc "$work/main.swift" "$work/Greeting.swift" -o "$work/swift-demo"
test "$("$work/swift-demo")" = 'Swift host OK'
printf '%s\n' 'C and multi-file Swift host smoke tests passed. Embedded iOS backend remains unavailable.'
