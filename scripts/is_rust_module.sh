#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# is_rust_module.sh MOD.ko
#
# Returns 0 if MOD.ko is a rust module, 1 otherwise.

set -e
module="$*"

while IFS= read -r line
do
  # Any symbol beginning with "_R" is a v0 mangled rust symbol
  if [[ $line =~ ^[0-9a-fA-F]+[[:space:]]+[uUtTrR][[:space:]]+_R[^[:space:]]+$ ]]; then
    exit 0
  fi
done < <(nm "$module")

exit 1
