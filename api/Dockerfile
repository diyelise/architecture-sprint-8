FROM python:3.8

RUN  apt-get update \
  && apt-get install -y wget \
  && rm -rf /var/lib/apt/lists/*

# python dependencies
COPY ./requirements.txt /
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r ./requirements.txt

COPY . /app
WORKDIR /app