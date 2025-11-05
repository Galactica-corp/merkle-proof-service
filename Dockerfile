FROM golang:1.22.2-alpine as builder

RUN apk add --no-cache make git gcc musl-dev linux-headers

WORKDIR /app
COPY go.mod go.sum ./

RUN go mod download
COPY . .

ARG DB_BACKEND=goleveldb
RUN make build DB_BACKEND=${DB_BACKEND}

FROM alpine:latest

WORKDIR /root/

RUN mkdir -p .galacticad-merkle

COPY --from=builder /app/build/galacticad-merkle .
ARG config_path=config/merkle-613419.yaml
COPY --from=builder /app/${config_path} ./.galacticad-merkle/merkle-613419.yaml

VOLUME /root/.galacticad-merkle

# grpc port
EXPOSE 50651
# grpc-gateway port
EXPOSE 8480

CMD ["./galacticad-merkle", "indexer", "start", "--home", ".galacticad-merkle"]
