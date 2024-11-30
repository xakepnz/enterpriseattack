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
	pip install -q .[test,build]
	pip install -q .
	pre-commit install
	pre-commit install --hook-type commit-msg

clean:
	@echo "Removing previous builds..."
	pip uninstall enterpriseattack -y
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf build dist enterpriseattack.egg-info .tox htmlcov .coverage coverage.xml .coverage.* .pytest_cache

build:
	make clean
	@echo "Building enterpriseattack..."
	python3 -m pip install -e .[build]
	python3 -m build .

test:
	@echo "Running tests..."
	pip install -q .[test]
	tox
