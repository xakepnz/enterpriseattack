# ----------------------------------------------------------------------------#

.PHONY: init install test cover clean

# ----------------------------------------------------------------------------#

VENV = venv

PYTHON = $(VENV)/bin/python
PRE_COMMIT = $(VENV)/bin/pre-commit
PIP_DEP_TREE = $(VENV)/bin/pipdeptree
PYTEST = $(VENV)/bin/pytest
TOX = $(VENV)/bin/tox

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
	$(TOX) --verbose

cover:
	${PYTEST} -vv --cov=./enterpriseattack --cov-config=.coveragerc \
	--cov-report=term-missing --cov-report=html

clean:
	@echo "Removing previous builds..."
ifeq ($(shell test -d venv && echo 1),1)
	$(PYTHON) -m pip uninstall enterpriseattack -y
else
	python3 -m pip uninstall enterpriseattack -y
endif
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf $(VENV) build dist enterpriseattack.egg-info .tox htmlcov .coverage coverage.xml .coverage.* results.* .pytest_cache

build:
	make clean
	make install
	@echo "Building enterpriseattack..."
	$(PYTHON) -m build

sbom:
	@echo "Building dependency SBOM"
	. $(VENV)/bin/activate && \
	$(PIP_DEP_TREE) --json > pipdeptree.json
