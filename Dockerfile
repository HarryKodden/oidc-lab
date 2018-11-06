FROM python:latest

MAINTAINER harry.kodden@surfnet.nl

RUN apt-get update

COPY requirements.txt .
RUN pip install -r requirements.txt

ADD oidc-lab.py /usr/local/bin/

EXPOSE 8000

CMD ["python", "/usr/local/bin/oidc-lab.py"]
