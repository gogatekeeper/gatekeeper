ARG HOMEDIR=/opt/gatekeeper

#
# Builder
#

FROM --platform=$BUILDPLATFORM golang:1.24 AS build-env
ARG HOMEDIR
ARG TARGETOS TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

ADD . /src/
WORKDIR /src/

RUN mkdir -p bin && \
    GIT_SHA=$(git --no-pager describe --always --dirty) && \
    BUILD_TIME=$(date '+%s') && \
    TAG=$(git describe --tags) && \
    NAME=gatekeeper && \
    LFLAGS=" -X github.com/gogatekeeper/gatekeeper/pkg/proxy/core.release=$TAG -X github.com/gogatekeeper/gatekeeper/pkg/proxy/core.gitsha=$GIT_SHA -X github.com/gogatekeeper/gatekeeper/pkg/proxy/core.compiled=$BUILD_TIME" && \
    CGO_ENABLED=0 go build -a -tags netgo -ldflags "-s -w ${LFLAGS}" -o bin/${NAME} cmd/keycloak/gatekeeper-keycloak.go

WORKDIR ${HOMEDIR}

RUN cp /src/bin/gatekeeper .
COPY templates ./templates

RUN echo "gatekeeper:x:1000:gatekeeper" >> /etc/group && \
    echo "gatekeeper:x:1000:1000:gatekeeper user:${HOMEDIR}:/sbin/nologin" >> /etc/passwd && \
    chown -R gatekeeper:gatekeeper ${HOMEDIR} && \
    chmod -R g+rw ${HOMEDIR} && \
    chmod +x gatekeeper

#
# Actual image
#

FROM scratch
ARG HOMEDIR

LABEL Name=gatekeeper \
      Release=https://github.com/gogatekeeper/gatekeeper \
      Url=https://github.com/gogatekeeper/gatekeeper \
      Help=https://github.com/gogatekeeper/gatekeeper/issues

COPY --chown=1000:1000 --from=build-env ${HOMEDIR} ${HOMEDIR}
COPY --from=build-env /etc/passwd /etc/passwd
COPY --from=build-env /etc/group /etc/group
COPY --from=build-env /usr/share/ca-certificates /usr/share/ca-certificates
COPY --from=build-env /etc/ssl/certs /etc/ssl/certs

WORKDIR ${HOMEDIR}
USER 1000
ENTRYPOINT [ "/opt/gatekeeper/gatekeeper" ]
