# Start from the latest Golang base image
FROM golang:alpine AS build-env

# Add Maintainer Info
LABEL maintainer="adharsh dev@adharsh.in"

# Add current directory to Docker image
ADD . /src

# Set the Current Working Directory inside the container
WORKDIR /src

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# This stage starts another, separate image using alpine:latest
FROM alpine:latest

# Set necessary environment variables needed for our image
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Move to /app
WORKDIR /app

# Copy binary from build stage
COPY --from=build-env /src/main /app/main

# Expose port 8080 to the outside
EXPOSE 8080

# Command to run the executable
CMD ["./main", "serve"]