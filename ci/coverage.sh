#!/bin/bash

# Copyright © 2017 VMware, Inc. All Rights Reserved.
# SPDX-License-Identifier: BSD-2-Clause

echo "mode: set" > profile.cov

DEPS=""

list_deps(){
	local pkg="${1?}"
	DEPS="${pkg}"
	ds="$(echo $(go list -f '{{.Imports}}' "${pkg}") | sed 's/[][]//g')"
	for d in ${ds}; do
		if echo "${d}" | grep -q "github.com/vmware/virtual-security-module"; then
			DEPS+=",${d}"
		fi
	done
}

build_cover_profile() {
	local packages=$(go list ./...)
	for p in ${packages}; do
		list_deps "${p}"
		go test -cover -coverprofile=cover.out -coverpkg "${DEPS}" "${p}"
		if [[ -f cover.out ]]; then
			tail -n+2 cover.out >> profile.cov
			rm -f cover.out
		fi
	done
}
main() {
	build_cover_profile
}

main