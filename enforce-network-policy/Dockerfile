FROM python:3.9-slim-buster

ENV DEBUG="false"
ENV ALLOWED_USER="kubernetes-admin"

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . /app

CMD [ "python3", "/app/webhook.py"]