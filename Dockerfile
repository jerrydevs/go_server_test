FROM debian:stable-slim

COPY out /bin/out

ENV PORT 8080

CMD ["/bin/out"]