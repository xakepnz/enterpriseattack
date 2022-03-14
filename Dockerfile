FROM python:3.9-alpine

COPY . /enterpriseattack

WORKDIR /enterpriseattack

RUN pip install -r /enterpriseattack/requirements.txt

RUN python setup.py install

HEALTHCHECK NONE

CMD [ "python", "/enterpriseattack/tests/test_benchmarks.py" ]
