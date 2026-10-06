# The Gryphon agent as a container image, for running inside a Kubernetes
# cluster (gryphon-agent.yaml beside this). goreleaser builds the binary and
# copies it in; see .goreleaser.yaml.
#
# distroless/static rather than scratch: the agent connects to Gryphon over
# TLS and needs the CA roots, and the CronJob check reads a CronJob's time zone,
# which needs the zone database. Both are in it, with nothing else -- no
# shell, no package manager -- and its nonroot user, 65532.
FROM gcr.io/distroless/static-debian12:nonroot
# goreleaser puts each platform's binary in a directory named for it
# (linux/amd64/gryphon-agent), and buildx says which platform this is.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/gryphon-agent /usr/bin/gryphon-agent
USER 65532:65532
ENTRYPOINT ["/usr/bin/gryphon-agent"]
