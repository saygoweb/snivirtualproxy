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

### Automated (recommended)

Run the setup script from the repository root:

```bash
sudo bash deploy/setup.sh
```

Options:

| Flag | Description |
|------|-------------|
| `--no-start` | Install and enable the service but do not start it |
| `--no-enable` | Install but do not enable or start the service |
| `--sample-config` | Overwrite an existing config with the sample (backs up first) |

The script will:
1. Install Go if not present
2. Build and install the binary to `/usr/local/sbin/snivirtualproxy`
3. Create `/etc/snivirtualproxy/config.yml` (if it doesn't exist)
4. Install and enable the systemd service

### Manual

- Build: `go build -o snivirtualproxy .`
- Copy the binary to `/usr/local/sbin/snivirtualproxy`
- Copy `deploy/snivirtualproxy.service` to `/etc/systemd/system/`
- Create `/etc/snivirtualproxy/config.yml` — see [config.yml](config.yml) for an example
- Reload and start:

```bash
systemctl daemon-reload
systemctl enable --now snivirtualproxy
```
