FROM busybox:latest
COPY subdscan subdscan
RUN ls
EXPOSE 80
ENTRYPOINT [ "./subdscan", "-ui", "80" ]