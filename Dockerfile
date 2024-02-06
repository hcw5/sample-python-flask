FROM python:latest

RUN apt-get update && apt-get install --yes pipenv
WORKDIR /usr/src/app

COPY ./ /usr/src/app/
RUN pipenv install --deploy --ignore-pipfile
CMD pipenv run pip install -r requirements.txt
RUN pip3 install --no-cache-dir -U -r requirements.txt
CMD python3 app.py
