# Single image, single binary, many subcommands.

FROM registry.access.redhat.com/ubi9/go-toolset:latest AS build

ARG VERSION=dev
ARG COMMIT=
ARG DATE=
ARG TARGETARCH

WORKDIR /src

# Dependencies first, so a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 so the binary runs on ubi9-micro, which has no libc toolchain.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/project-lightpath/cli-tools/internal/version.Version=${VERSION} \
        -X github.com/project-lightpath/cli-tools/internal/version.Commit=${COMMIT} \
        -X github.com/project-lightpath/cli-tools/internal/version.Date=${DATE}" \
      -o /out/tssc ./cmd/tssc


FROM registry.access.redhat.com/ubi9/ubi-micro:latest

COPY --from=build /out/tssc /usr/bin/tssc

# Tekton overrides this, but a non-root default keeps the image usable under a
# restricted SCC and matches what the pipeline's SecurityContext expects.
USER 1001

ENTRYPOINT ["/usr/bin/tssc"]
