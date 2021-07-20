FROM python:3.8-slim-buster

WORKDIR /app

#RUN pip3 install Flask request jsonify &&  pip3 freeze > requirements.txt

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . /app

CMD [ "python3", "/app/webhook.py"]