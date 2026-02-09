.PHONY: test test-install test-purge

test: test-install
	bats test/

test-install:
	@command -v bats >/dev/null 2>&1 || brew install bats-core

# Run a single test file: make test-keychain, make test-exec, etc.
test-%: test-install
	bats test/$*.bats

# Safety net: purge any orphaned test secrets
test-purge:
	@SV_SERVICE_PREFIX="sv_test:" && \
	keys=$$(security dump-keychain 2>/dev/null \
		| grep '"svce"<blob>="sv_test:' \
		| sed 's/.*"sv_test:\(.*\)"/\1/' \
		| sort -u) && \
	if [ -z "$$keys" ]; then \
		echo "No orphaned test secrets found."; \
	else \
		echo "Purging orphaned test secrets:"; \
		echo "$$keys" | while IFS= read -r key; do \
			echo "  removing $$key"; \
			security delete-generic-password -a "$$USER" -s "sv_test:$$key" >/dev/null 2>&1 || true; \
		done; \
		echo "Done."; \
	fi
