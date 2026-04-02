.PHONY: test test-install test-purge test-keychain test-pass

test: test-install
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		bats test/exec.bats test/keychain.bats test/manifest.bats test/validation.bats; \
	elif [ "$$(uname -s)" = "Linux" ]; then \
		bats test/exec.bats test/manifest.bats test/pass.bats test/validation.bats; \
	else \
		echo "sv tests only support macOS and Linux."; \
		exit 1; \
	fi

test-install:
	@command -v bats >/dev/null 2>&1 || { echo "Install bats-core to run tests."; exit 1; }

# Run a single test file: make test-keychain, make test-exec, etc.
test-keychain: test-install
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		bats test/keychain.bats; \
	else \
		echo "Keychain tests only run on macOS."; \
	fi

test-pass: test-install
	@if [ "$$(uname -s)" = "Linux" ]; then \
		bats test/pass.bats; \
	else \
		echo "pass tests only run on Linux."; \
	fi

test-%: test-install
	bats test/$*.bats

# Safety net: purge any orphaned test secrets
test-purge:
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		SV_SERVICE_PREFIX="sv_test:"; \
		keys=$$(security dump-keychain 2>/dev/null \
			| grep '"svce"<blob>="sv_test:' \
			| sed 's/.*"sv_test:\(.*\)"/\1/' \
			| sort -u); \
		if [ -z "$$keys" ]; then \
			echo "No orphaned test secrets found."; \
		else \
			echo "Purging orphaned test secrets:"; \
			echo "$$keys" | while IFS= read -r key; do \
				echo "  removing $$key"; \
				security delete-generic-password -a "$$USER" -s "sv_test:$$key" >/dev/null 2>&1 || true; \
			done; \
			echo "Done."; \
		fi; \
	else \
		echo "Linux tests use temporary password stores; nothing to purge."; \
	fi
