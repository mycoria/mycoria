FROM golang:1.22 as builder

# Ensure ca-certficates are up to date
RUN update-ca-certificates

# Install dependencies
WORKDIR $GOPATH/src/github.com/mycoria/mycoria
COPY go.mod .
COPY go.sum .
ENV GO111MODULE=on
RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Build the static binary
RUN cd cmd/mycoria && \
./build -o /go/bin/mycoria

# Use static image
# https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/static-debian12

# Copy our static executable
COPY --from=builder --chmod=0755 /go/bin/mycoria /opt/mycoria/mycoria

# Run the mycoria binary.
ENTRYPOINT ["/opt/mycoria/mycoria"]
CMD ["run"]
