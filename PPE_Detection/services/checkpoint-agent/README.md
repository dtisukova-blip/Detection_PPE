# Checkpoint Agent Service

Local checkpoint service with:

- built-in web UI
- control-center discovery and registration
- heartbeat and config pull loops
- image upload and inspection flow
- local event and inspection history

## Standalone Docker run

```bash
cd services/checkpoint-agent
docker compose up --build
```

Important:

- set a real `CHECKPOINT_LOCAL_URL` if the service must be reachable from another machine
- use an explicit `control_center_url` in bootstrap such as `https://<host>:8000`
- use `control_center_runtime_url` for runtime mTLS such as `https://<host>:8443`
- do not rely on `checkpoint-agent:8020` or other Docker service-name addresses outside the single-network dev setup
- standalone compose uses `network_mode: host`, so on one Linux machine the local bootstrap values can simply be `https://127.0.0.1:8000`, `https://127.0.0.1:8443`, and `https://127.0.0.1:8020`
- after service certificate enrollment, restart the checkpoint agent once so its UI listener switches from plain HTTP startup mode to HTTPS
