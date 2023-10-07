FROM debian:stable-slim 
RUN #!/bin/bash
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources

RUN apt-get update
RUN apt-get install -y socat  
RUN apt-get install -y wget 
RUN wget https://golang.google.cn/dl/go1.17.8.linux-amd64.tar.gz
RUN mkdir codes
RUN tar -C /codes -xzf go1.17.8.linux-amd64.tar.gz 

RUN cd root
RUN rm -rf .bashrc
COPY .bashrc .
RUN source .bashrc
RUN cd ../ 


WORKDIR /app
COPY main.go .
COPY templates/* .

RUN go mod init github.com/AL3XEI709/Geek23/tree/main/GoGoCrypto
RUN go get -u github.com/gin-gonic/gin@v1.6.3
EXPOSE 7777
CMD ["/bin/sh", "-c", "socat TCP-LISTEN:7777,fork,reuseaddr EXEC:'go run main.go',stderr"]
