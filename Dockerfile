# build stage
FROM golang:1.21 AS build
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nests-api /app/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nests-front /app/cmd/front/main.go

# runtime stage
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=build /out/nests-api /app/nests-api
COPY --from=build /out/nests-front /app/nests-front
COPY --from=build /app/front /app/front
COPY --from=build /app/data /app/data
COPY --from=build /app/start.sh /app/start.sh
ENV NESTS_PORT=7766
ENV NESTS_API_BASE=http://localhost:7766
ENV NESTS_DATA_DIR=/app/data
EXPOSE 7766 7788
ENTRYPOINT ["/app/start.sh"]
