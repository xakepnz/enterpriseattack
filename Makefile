venv-dir := '.venv'

.PHONY: init
.PHONY: clean
.PHONY: build
.PHONY: install

init:
	make install

install:
	@echo "Installing enterpriseattack..."
	python3 -m venv $(venv-dir)
	. $(venv-dir)/bin/activate
	$(venv-dir)/bin/pip install -q .
	$(venv-dir)/bin/pip install -q .[test,build]
	pre-commit install
	pre-commit install --hook-type commit-msg

clean:
	@echo "Removing previous builds..."
	$(venv-dir)/bin/pip uninstall enterpriseattack -y
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf build dist enterpriseattack.egg-info .tox htmlcov .coverage coverage.xml .coverage.* .pytest_cache

build:
	make clean
	@echo "Building enterpriseattack..."
	$(venv-dir)/bin/pip install -q .[build]
	$(venv-dir)/bin/python3 -m build

test:
	@echo "Running tests..."
	$(venv-dir)/bin/pip install -q .[test]
	$(venv-dir)/bin/tox
