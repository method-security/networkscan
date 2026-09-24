# Basic Usage

## Binaries

Running as a binary allows you to skip dealing with any container related networking issues and leverage the same network interface that the host machine is using.

You can validate the binary against services running on your own machine. A CONNECT scan does not require raw-packet privileges.

```bash
networkscan discover port --target 127.0.0.1 --ports 22,80 --scan-type CONNECT
```

## Docker

Running networkscan within a Docker container should typically work similarly to running directly on a host, however, occasionally there are a few things to keep in mind.

If you're running on a Docker container on a MacOS machine and you are trying to scan a locally running service, you can leverage the `host.docker.internal` address as mentioned in the Docker documentation [here](https://docs.docker.com/desktop/networking/#i-want-to-connect-from-a-container-to-a-service-on-the-host).

```bash
docker run --rm ghcr.io/method-security/networkscan discover port --target host.docker.internal --ports 22,80 --scan-type CONNECT
```

Inside a container, `127.0.0.1` refers to the container itself, not the Docker host. On Linux, add `--add-host=host.docker.internal:host-gateway` to the Docker command when using this hostname.
