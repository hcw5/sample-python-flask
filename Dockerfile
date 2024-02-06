FROM python:latest

RUN apt-get update && apt-get install --yes pipenv
WORKDIR /usr/src/app

COPY ./ /usr/src/app/
RUN pipenv install --deploy --ignore-pipfile
CMD pipenv run pip install -r requirements.txt
CMD pipenv run python app.py
