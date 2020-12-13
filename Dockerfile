#
# Builder image
#

FROM golang:1.14.4 AS build-env
ARG SOURCE=*

ADD $SOURCE /src/
WORKDIR /src/

# Unpack any tars, then try to execute a Makefile, but if the SOURCE url is
# just a tar of binaries, then there probably won't be one. Using multiple RUN
# commands to ensure any errors are caught.
RUN find . -name '*.tar.gz' -type f | xargs -rn1 tar -xzf
RUN if [ -f Makefile ]; then make; fi
RUN cp "$(find . -name 'gatekeeper' -type f -print -quit)" /gatekeeper

#
# Actual image
#

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.2

LABEL Name=gatekeeper \
      Release=https://github.com/go-gatekeeper/gatekeeper \
      Url=https://github.com/go-gatekeeper/gatekeeper \
      Help=https://github.com/go-gatekeeper/gatekeeper/issues

WORKDIR "/opt/gatekeeper"

RUN echo "gatekeeper:x:1000:gatekeeper" >> /etc/group && \
    echo "gatekeeper:x:1000:1000:gatekeeper user:/opt/gatekeeper:/sbin/nologin" >> /etc/passwd && \
    chown -R gatekeeper:gatekeeper /opt/gatekeeper && \
    chmod -R g+rw /opt/gatekeeper

COPY templates ./templates
COPY --from=build-env /gatekeeper ./
RUN chmod +x gatekeeper

USER 1000
ENTRYPOINT [ "/opt/gatekeeper/gatekeeper" ]
