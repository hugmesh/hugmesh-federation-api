# Snapdragon federation-api — developer make targets.
#
# `make pentest` runs the repo-local pen-test self-scan that mirrors the GitLab CI
# `pentest` stage (snapdragon-generator tests/pentest/ci/pentest-stage.gitlab-ci.yml):
#   * SCA  — OWASP Dependency-Check over this Maven project (CVSS>=9 fails the build,
#            matching the CI dependency-check job).
#   * DAST — when DAST_TARGET_URL is set, delegates to the canonical generator harness
#            (tests/pentest/run-pentest.sh) which drives the authenticated ZAP scan +
#            the custom escalation/DoS probes + nuclei. Advisory: skipped (no hard
#            fail) when no target / no tooling is available.
#
# Self-contained: never hard-fails when DAST tooling or a target is missing.

SHELL := /bin/bash

# Allow running dependency-check inside the same image CI uses, or directly via the
# project wrapper when a local JDK is present. Override on the command line if needed.
JDK_IMAGE        ?= eclipse-temurin:21-jdk-noble
DEP_CHECK_DATA   ?= .dep-check-data
SCA_FAIL_CVSS    ?= 9

# DAST harness (canonical, in snapdragon-generator). Override GENERATOR_DIR if the
# generator checkout lives elsewhere; the target clones it on demand otherwise.
GENERATOR_DIR    ?= ../snapdragon-generator
GENERATOR_REPO   ?= https://github.com/Snapdragon-Systems/snapdragon-generator.git
PENTEST_HARNESS  ?= $(GENERATOR_DIR)/tests/pentest/run-pentest.sh

.PHONY: pentest pentest-sca pentest-dast

pentest: pentest-sca pentest-dast ## Run the local pen-test self-scan (SCA + optional DAST), mirroring CI.

# --- SCA: OWASP Dependency-Check over this Maven project (mirrors CI) ----------
pentest-sca: ## OWASP Dependency-Check SCA over this repo (CVSS>=$(SCA_FAIL_CVSS) fails).
	@echo "[pentest-sca] OWASP Dependency-Check (failOnCVSS=$(SCA_FAIL_CVSS))"
	@mkdir -p $(DEP_CHECK_DATA)
	@if command -v docker >/dev/null 2>&1; then \
		echo "[pentest-sca] running via $(JDK_IMAGE) (as CI does)"; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-v "$(CURDIR)/$(DEP_CHECK_DATA):/dep-check-data" \
			-w /workspace \
			--entrypoint "" \
			$(JDK_IMAGE) \
			./mvnw org.owasp:dependency-check-maven:check \
				-Dformat=HTML,JSON \
				-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
				-DdataDirectory=/dep-check-data \
				-DautoUpdate=true \
				-B; \
	else \
		echo "[pentest-sca] docker not found — running with local ./mvnw"; \
		./mvnw org.owasp:dependency-check-maven:check \
			-Dformat=HTML,JSON \
			-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
			-DdataDirectory=$(DEP_CHECK_DATA) \
			-DautoUpdate=true \
			-B; \
	fi

# --- DAST: delegate to the canonical generator harness (advisory) --------------
pentest-dast: ## Authenticated ZAP DAST + probes + nuclei via the generator harness; needs DAST_TARGET_URL.
	@if [ -z "$${DAST_TARGET_URL:-}" ]; then \
		echo "[pentest-dast] DAST_TARGET_URL not set — skipping live scan (advisory)."; \
		echo "[pentest-dast] Set it to a running test env, e.g.:"; \
		echo "[pentest-dast]   DAST_TARGET_URL=http://gateway.test-env:8080 make pentest-dast"; \
		exit 0; \
	fi; \
	if [ ! -f "$(PENTEST_HARNESS)" ]; then \
		echo "[pentest-dast] harness not found at $(PENTEST_HARNESS)."; \
		echo "[pentest-dast] clone the generator, then re-run, e.g.:"; \
		echo "[pentest-dast]   git clone $(GENERATOR_REPO) $(GENERATOR_DIR)"; \
		echo "[pentest-dast]   bash $(PENTEST_HARNESS) --env target --target \"$$DAST_TARGET_URL\" --scan baseline"; \
		echo "[pentest-dast] skipping (advisory)."; \
		exit 0; \
	fi; \
	echo "[pentest-dast] running canonical harness against $$DAST_TARGET_URL"; \
	bash "$(PENTEST_HARNESS)" --env target --target "$$DAST_TARGET_URL" --scan baseline --pipeline main
