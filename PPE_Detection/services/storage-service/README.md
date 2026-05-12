# Storage Service

Local storage / delivery service with:

- built-in web UI
- control-center discovery and registration
- heartbeat and config pull loops
- polling and execution of delivery tasks
- local history and event log

## Standalone Docker run

```bash
cd services/storage-service
docker compose up --build
```

Important:

- set a real `STORAGE_LOCAL_URL` if the service must be reachable from another machine
- use an explicit `control_center_url` in bootstrap such as `https://<host>:8000`
- use `control_center_runtime_url` for runtime mTLS such as `https://<host>:8443`
- do not rely on `storage-service:8040` or other Docker service-name addresses outside the single-network dev setup
- standalone compose uses `network_mode: host`, so on one Linux machine the local bootstrap values can simply be `https://127.0.0.1:8000`, `https://127.0.0.1:8443`, and `https://127.0.0.1:8040`
- after service certificate enrollment, restart the delivery adapter once so its UI listener switches from plain HTTP startup mode to HTTPS
