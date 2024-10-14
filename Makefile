.PHONY: install clean build publish test coverage

VENV := .venv/bin

init:
	python3 -m venv .venv

install:
	make init
	$(VENV)/pip install -r requirements.txt
	$(VENV)/pip install -r requirements-dev.txt
	$(VENV)/pre-commit install
	$(VENV)/pre-commit install --hook-type commit-msg

test:
	$(VENV)/tox --parallel auto

coverage:
	$(VENV)/py.test -s -vv --cov-report=term --cov-report=html --cov=enterpriseattack --cov-report=term-missing -cov-config=.coveragerc tests

clean:
	rm -fr build dist .egg enterpriseattack.egg-info report.xml htmlcov pyvenv.cfg venv lib include bin .pytest_cache .coverage .tox

build:
	make install
	$(VENV)/python setup.py sdist bdist_wheel --universal
