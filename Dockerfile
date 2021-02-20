FROM golang:alpine as build

RUN apk update
RUN apk add git upx gcc musl-dev
ADD . /app
WORKDIR /app
RUN go build -ldflags="-s -w" -v -o server ./verifyserver
RUN upx --lzma /app/server

FROM alpine:latest
COPY --from=build /app /app
EXPOSE 59710
WORKDIR /app
CMD /app/server
