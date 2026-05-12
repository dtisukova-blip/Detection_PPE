from __future__ import annotations

import multiprocessing
import ssl

import uvicorn

from control_center.app import app
from control_center.config import get_ui_host, get_pki_dir, get_runtime_port, get_tls_public_hosts, get_ui_port, is_runtime_mtls_enabled
from control_center.pki import ensure_internal_ca, get_paths


__all__ = ["app"]


def _run_ui() -> None:
    pki_dir = get_pki_dir()
    ensure_internal_ca(pki_dir, get_tls_public_hosts())
    paths = get_paths(pki_dir)
    uvicorn.run(
        app,
        host=get_ui_host(),
        port=get_ui_port(),
        ssl_keyfile=str(paths.control_center_key),
        ssl_certfile=str(paths.control_center_cert),
    )


def _run_runtime() -> None:
    pki_dir = get_pki_dir()
    ensure_internal_ca(pki_dir, get_tls_public_hosts())
    paths = get_paths(pki_dir)
    kwargs = {}
    if is_runtime_mtls_enabled():
        kwargs["ssl_ca_certs"] = str(paths.root_cert)
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    uvicorn.run(
        app,
        host=get_ui_host(),
        port=get_runtime_port(),
        ssl_keyfile=str(paths.control_center_key),
        ssl_certfile=str(paths.control_center_cert),
        **kwargs,
    )


if __name__ == "__main__":
    ui = multiprocessing.Process(target=_run_ui)
    runtime = multiprocessing.Process(target=_run_runtime)
    ui.start()
    runtime.start()
    ui.join()
    runtime.join()
