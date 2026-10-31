FROM ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates python3 cmake make perl gcc-mingw-w64-x86-64-posix \
    g++-mingw-w64-x86-64-posix binutils-mingw-w64-x86-64 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY . /recipe/
RUN python3 /recipe/fetch.py /work/sources && bash /recipe/build.sh /work/sources /work/build /work/output
FROM scratch AS export
COPY --from=build /work/output/ /
