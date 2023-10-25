FROM python:3.9

RUN apt-get update

COPY requirements.txt .
RUN pip install -r requirements.txt

ADD oidc-lab.py /usr/local/bin/

RUN echo "Europe/Amsterdam " > /etc/timezone
RUN dpkg-reconfigure -f noninteractive tzdata

EXPOSE 8000

CMD ["python", "/usr/local/bin/oidc-lab.py"]
