# MQTT-Security-Scanner


## Background
MQTT Deployment Baseline Scanner is a MQTT deployment security baseline scanning tool, designed to assess and ensure that a MQTT deployment meets minimum security requirements.


## Get Started

Download `MQTT-Security-Scanner` from [Release](https://github.com/emqx/mqtt-security-scanner/releases).
Make sure to have your configuration JSON file ready. Run the program and pass your configuration file as a command line argument.

``` bash
# example
version="1.0.0"
os="darwin"
arch="arm64"

wget "https://github.com/emqx/mqtt-security-scanner/releases/download/v${version}/mqtt-security-scanner_${version}_${os}_${arch}.tar.gz"

tar -xzvf mqtt-security-scanner_${version}_${os}_${arch}.tar.gz

# modify config/config.json

./mqtt-security-scanner -config=config/config.json
```
Enjoy securing your MQTT deployments!


## Configuration
You can specify the parameters of the tool using a configuration file in JSON format. The keys in this file have the following meanings:

### Broker Info
- host: The hostname or IP address of the broker.
- mqtt_port: The MQTT port (default is 1883).
- ws_port: The Websocket port (default is 8083).
- mqtts_port: The MQTT secure port (default is 8883).
- wss_port: The secure Websocket port (default is 8084).
- username: The username to authenticate with the MQTT broker.
- password: The password to authenticate with the MQTT broker.
- deny_topics: A list of topics that should be denied.

### Limit
- client_id_len: The maximum allowable length for a client ID.
- username_len: The maximum allowable length for a username.
- password_len: The maximum allowable length for a password.
- support_tls_versions: A list of TLS versions that should be supported (expressed as integer values).
- unsupported_tls_versions: A list of TLS versions that should not be supported (expressed as integer values).
- topic_level: The maximum allowable number of topic levels.
- topic_len: The maximum allowable length for a topic.
- payload_len: The maximum allowable payload length (in MB).
- connection: The maximum number of concurrent connections.

### Hosts
- A list of agent hosts need to be scanned.


## Scan Items
MQTT Security Baseline Scanner performs scans under the following categories:

### Protocol
- **Invalid MQTT Message Format:** Check if the broker accepts invalid MQTT protocol connections.
- **Invalid Websocket Message Format:** Check if the broker accepts invalid Websocket protocol connections.
- **TLS Version:** Checks the supported and unsupported versions of TLS in the MQTT broker.

### Client
- **Client Authentication:** Checks the client connections with valid, no and wrong username/password.
- **Client Username Length:** Checks if a client with an excessive username length can connect to the MQTT broker.
- **Client Password Length:** Checks if a client with an excessive password length can connect to the MQTT broker.
- **Client ID Length:** Checks if a client with an excessive ID length can connect to the MQTT broker.
- **Client Flapping:** Checks if a client is added to a blacklist after frequent connect/disconnect cycles, also known as flapping.
- **Client Connection:** Tests the maximum number of concurrent connections a MQTT broker can handle.

### Message
- **Deny Topic:** Checks if the MQTT broker denies messages to certain topics specified in the configuration.
- **Topic Level:** Checks if the MQTT broker supports a topic with more levels than the defined limit.
- **Topic Length:** Checks if the MQTT broker supports a topic length larger than the specified limit.
- **Message Payload Length:** Checks if the MQTT broker can support a message payload length larger than the specified limit.

### Port
- **Broker and Agent Port Scan:** Scans all open ports on the broker and agent hosts, ensuring no unwanted ports are open.


## License
See [LICENSE](https://github.com/emqx/mqtt-security-scanner/blob/main/LICENSE)