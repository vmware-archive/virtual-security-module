#!/bin/bash

# Copyright © 2017 VMware, Inc. All Rights Reserved.
# SPDX-License-Identifier: BSD-2-Clause

PROFILE="profile.cov"
IS_COVERALLS="false"
SHOW_COVER_REPORT="false"
MODE="count"
echo "mode: ${MODE}" > "${PROFILE}"

get_opts() {
	while [[ -n "${1}" ]]; do
		opt="${1}"
		val="${opt#*=}"
		shift
		case "${opt}" in
			--coveralls)
				IS_COVERALLS="true"
				;;
			--show-cover-report)
				SHOW_COVER_REPORT="true"
				;;
			--help|-h)
				usage
				exit 0
				;;
		esac
	done
}



generate_cover_data() {
	for pkg in "${@}"; do
                f="$(echo "${pkg}" | tr / -).cover"
                go test -covermode="${MODE}" -coverprofile="${f}" "${pkg}"
	done

	grep -h -v "^mode:" *.cover >> "${PROFILE}"
	rm -f *.cover
}

push_to_coveralls() {
	echo "Pushing coverage statistics to coveralls.io"
	goveralls -coverprofile="${PROFILE}" -service=travis-ci
}

show_cover_report() {
	go tool cover -func="${PROFILE}"
}

main() {
	get_opts "${@}"
	generate_cover_data $(go list ./...)

	if "${SHOW_COVER_REPORT}"; then
		show_cover_report
	fi

	if "${IS_COVERALLS}"; then
		push_to_coveralls
	fi
}

main "${@}"