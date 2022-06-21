
# Simple Chimera CLI (Client and Server)

This tool runs as as transparent proxy. There is an included (configured) way to
run squid proxy in a docker container.

## Running

Server

```sh
CHIMERA=SERVER & ./chimera_cli
```

Client

```sh
./chimera_cli
```

For explicit debug information you can set the log level environment variable
for the quic-go library (supports levels debug, info, error, and nothing
(default nothing)) as well as the log level for the cli (supports DEBUG, INFO,
WARN, and ERROR (default INFO)).

```sh
# server
CHIMERA=SERVER QUIC_GO_LOG_LEVEL=debug ./chimera_cli -logLevel=DEBUG

# client
QUIC_GO_LOG_LEVEL=debug ./chimera_cli -logLevel=DEBUG
```

## Stream Handlers

The server can be configured to use one of sever handlers for incoming streams
based on the desired test / functionality for the server.

### Echo (Default)

Default stream handler - transparent echo of anything written to the endpoint.

### Static Transparent Forwarding

Opens a connection to a static address per stream and transparently forwards any
bytes received bidirectionally

```sh
CHIMERA=SERVER ./chimera_cli -forward "127.0.0.1:1234"
```

### Squid

Configured static forward handler that forwards to a local instance of squid
proxy to allow for http(s) proxy functionality. Runs squid in docker using
the [datadog/squid](https://hub.docker.com/r/datadog/squid) docker image. Squid
proxy parameters can be modified in `squid/squid.conf`.

**Note** the passwords file is included to be used as an example and default for testing - you should not deploy using those credentials in any way.

1. Run the Squid docker image

    ```sh
    # pull image if not available locally already
    docker pull datadog/squid

    cd squid && ./start_squid.sh
    ```

2. Run the server

    ```sh
    $ CHIMERA=SERVER ./chimera_cli -forward "127.0.0.1:3128"
    2022/05/31 10:54:19 [NOTICE]: chimera-proxy-0.0.1 - launching
    2022/05/31 10:54:19 [INFO]: chimera_cli - initializing server transport listeners
    2022/05/31 10:54:19 [INFO]: registered listener(s): [::]:57007
    2022/05/31 10:54:19 [INFO]: chimera_cli - accepting connections
    ```

3. Run the client

    ```sh
    $ ./chimera_cli
    2022/05/31 10:54:44 [NOTICE]: chimera-proxy-0.0.1 - launching
    2022/05/31 10:54:44 [INFO]: chimera_cli - initializing client transport listeners
    2022/05/31 10:54:44 [INFO]: registered listener: 127.0.0.1:10500
    2022/05/31 10:54:44 [INFO]: chimera_cli - accepting connections
    ```

4. Configure local proxy

    ```sh
    export http_proxy="http://admin:changeme@127.0.0.1:10500"
    export https_proxy=$http_proxy

    // Use curl to pull (and check the server Info -I of) a website over the tunnel.
    curl https://jack.wampler.co -I -v
    ```

    To disable proxying unset the proxy environment variables.

    ```sh
    unset http_proxy https_proxy
    ```

5. Stop (and clean) Squid docker image

    ```sh
    docker stop squid
    docker rm squid
    ```

### HTTP

Not yet implemented
