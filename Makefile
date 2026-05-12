.PHONY: help build vendor malware-db dist update-malware-data test smoke clean lint init

PY ?= $(shell command -v python3.14 python3.13 python3.12 python3.11 python3.10 2>/dev/null | head -1)
ifeq ($(PY),)
$(error No python>=3.10 binary on PATH (tried python3.14..python3.10). Install one or pass PY=/path/to/python)
endif

help:
	@echo "make build          - vendor third-party deps + bundle into dist/scs.py"
	@echo "make vendor         - fetch + verify pinned wheels into src/scs/_vendor/ (>=7 days old, hash-checked)"
	@echo "make malware-db     - compact OSSF dataset into dist/scs-malware-db.bin (separate sidecar)"
	@echo "make dist           - both: build + malware-db"
	@echo "make update-malware-data - bump the OSSF submodule to upstream HEAD"
	@echo "make test           - run unit tests"
	@echo "make smoke          - build + scan tests/fixtures/* and open the report"
	@echo "make lint           - byte-compile everything as a quick sanity check"
	@echo "make clean          - remove dist/, build/, vendored deps, caches"

build: vendor
	$(PY) build.py bundle --out dist/scs.py

vendor:
	$(PY) build.py vendor --vendor-file vendor.txt --out src/scs/_vendor

malware-db:
	$(PY) build.py compact-malware-db \
	    --src github.com--ossf--malicious-packages/osv/malicious \
	    --out dist/scs-malware-db.bin

dist: build malware-db

update-malware-data:
	git submodule update --remote github.com--ossf--malicious-packages

test: vendor
	PYTHONPATH=src:tests $(PY) -m unittest discover -s tests -v

smoke: build
	@if [ -f dist/scs-malware-db.bin ]; then \
		./dist/scs.py scan tests/fixtures/* --out /tmp/scs-smoke.html --offline --fail-on=none --malware-db dist/scs-malware-db.bin; \
	else \
		./dist/scs.py scan tests/fixtures/* --out /tmp/scs-smoke.html --offline --fail-on=none; \
	fi
	@echo ""
	@echo "    open /tmp/scs-smoke.html"
	@echo ""

lint:
	$(PY) -m compileall -q src tests build.py

clean:
	rm -rf dist/scs.py dist/scs-malware-db.bin build src/scs/_vendor/tomli src/scs/_vendor/packaging
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
