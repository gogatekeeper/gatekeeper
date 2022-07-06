ARG HOMEDIR=/opt/gatekeeper

#
# Builder
#

FROM golang:1.17.6 AS build-env
ARG HOMEDIR

ADD . /src/
WORKDIR /src/

RUN make static

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
