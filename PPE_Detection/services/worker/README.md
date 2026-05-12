# Worker Service

Local worker service with:

- built-in web UI
- control-center discovery and registration
- heartbeat and config pull loops
- local asyncio job queue fed by Control Center push
- Ultralytics PPE processing pipeline

## Standalone Docker run

```bash
cd services/worker
docker compose up --build
```

Important:

- set a real `WORKER_LOCAL_URL` if the service must be reachable from another machine
- use an explicit `control_center_url` in bootstrap such as `https://<host>:8000`
- use `control_center_runtime_url` for runtime mTLS such as `https://<host>:8443`
- do not rely on `worker:8010` or other Docker service-name addresses outside the single-network dev setup
- standalone compose uses `network_mode: host`, so on one Linux machine the local bootstrap values can simply be `https://127.0.0.1:8000`, `https://127.0.0.1:8443`, and `https://127.0.0.1:8010`
- after service certificate enrollment, restart the worker once so its UI listener switches from plain HTTP startup mode to HTTPS
