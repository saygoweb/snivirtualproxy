# SNI Virtual Proxy
A server that provides 'lazy loaded' named virtual SSL servers based on the servername given via SNI.

## How it Works

The server binds to the local port `server|bind`

When an SSL connection is established the private key and certificate are loaded by substituting the SNI servername $(SNI_SERVER_NAME) in the templates for `ssl|certificate` and `ssl|key` given in the configuration file.

Content is provided to the connection by reverse proxy to the backend server `server|upstreamurl`.

## Sample Configuration

```yaml
logfile: './snivirtualproxy.log'

server:
  bind: ":8453"
  upstreamurl: "http://localhost:8890"

ssl:
  certificate: "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/cert.pem"
  key: "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/privkey.pem"
```

## Commandline Usage

```yaml
Usage of snivirtualproxy:
  -config string
        Configuration file (default "/etc/snivirtualproxy/config.yml")
  -version
        Display version and exit
```

## Installation
- Copy the binary `snivirtualproxy` to `/usr/local/sbin`
- Copy the `config/snivirtualproxy.service` to `/etc/systemd/system/`
- Create a configuration file in `/etc/snivirtualproxy/config.yml`. See this [example](config.yml) for details.

Start the snivirtualproxy service
```
systemctl start snivirtualproxy
```
