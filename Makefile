# ----------------------------------------------------------------------------#

.PHONY: init
.PHONY: install
.PHONY: clean
.PHONY: build
.PHONY: sbom

# ----------------------------------------------------------------------------#

VENV = venv

PYTHON = $(VENV)/bin/python
PRE_COMMIT = $(VENV)/bin/pre-commit
PIP_DEP_TREE = $(VENV)/bin/pipdeptree

# ----------------------------------------------------------------------------#

init:
	make install

install:
	@echo "Installing enterpriseattack..."
	python3 -m venv venv
	. $(VENV)/bin/activate && \
	$(PYTHON) -m pip install -q . &&\
	$(PYTHON) -m pip install -q .[test,build,release] &&\
	$(PRE_COMMIT) install &&\
	$(PRE_COMMIT) install --hook-type commit-msg

test:
	tox --parallel auto

coverage:
	py.test --cov-config=.coveragerc --verbose --cov-report=term --cov-report=xml --cov=enterpriseattack tests/test_benchmarks.py
	coveralls

clean:
	@echo "Removing previous builds..."
ifeq ($(shell test -d venv && echo 1),1)
	$(PYTHON) -m pip uninstall enterpriseattack -y
else
	python3 -m pip uninstall enterpriseattack -y
endif
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf $(VENV) build dist enterpriseattack.egg-info .tox htmlcov .coverage coverage.xml .coverage.* results.* .pytest_cache

sbom:
	@echo "Building dependency SBOM"
	. $(VENV)/bin/activate && \
	$(PIP_DEP_TREE) --json > pipdeptree.json

build:
	make clean
	make install
	@echo "Building enterpriseattack..."
	$(PYTHON) -m build
