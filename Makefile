PYTHON ?= python3

.PHONY: test check demo clean

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

check:
	$(PYTHON) -m compileall -q src tests

demo:
	PYTHONPATH=src $(PYTHON) -m agent_sbom demo --out artifacts/demo

clean:
	$(PYTHON) -c "import shutil; shutil.rmtree('artifacts', ignore_errors=True)"
