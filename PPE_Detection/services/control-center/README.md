# Control Center Service

Control Center is the central service for:

- operator AAA
- registered service inventory
- scoped access control
- audit logging
- built-in operator web UI

## Service-local files

```text
services/control-center/
  main.py
  requirements.txt
  Dockerfile
  control_center/
```

## Local run

```bash
cd services/control-center
python3 main.py
```

## Docker

Standalone:

```bash
cd services/control-center
docker compose up --build
```

If operators or runtime services reach `control-center` by a LAN IP or DNS name, include that name in:

```text
CONTROL_CENTER_TLS_HOSTS=localhost,127.0.0.1,192.168.31.159,control-center.tailnet
```

On startup `control-center` will reissue its own server certificate if the configured SAN set changes.

Repository-root compose is still available for local all-in-one development, but it is not the recommended mental model for multi-host deployment testing.

The standalone compose file uses `network_mode: host`, so on Linux the service is reachable directly on:

- `https://127.0.0.1:8000` for operator UI and bootstrap enrollment
- `https://127.0.0.1:8443` for runtime mTLS traffic
