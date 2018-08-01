FROM ubuntu:latest

RUN apt-get update && apt-get install -y tshark net-tools sudo

ADD ./bin/sqlidetect /

ADD ./entrypoint.sh /

CMD ["/entrypoint.sh"]
