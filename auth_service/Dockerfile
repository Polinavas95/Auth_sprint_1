# Builds the requirements and runs the auth service

FROM python:3.10-alpine as uwsgi-builder

RUN apk add --no-cache linux-headers g++
RUN pip install --no-cache-dir --upgrade pip==22.3.1

COPY requirements.txt requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir=/root/wheels -r requirements.txt


FROM python:3.10-alpine
WORKDIR /opt/app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt requirements.txt
COPY --from=uwsgi-builder /root/wheels /root/wheels

RUN pip install \
    --no-index \
    --no-cache-dir \
    --find-links=/root/wheels \
    -r requirements.txt

RUN rm -rf /root/wheels

CMD ["python", "main.py"]
