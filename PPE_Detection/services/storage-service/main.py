from __future__ import annotations

import uvicorn

from storage_service.app import app
from storage_service.config import get_host, get_pki_dir, get_port
from storage_service.tls import cert_path, has_tls_material, key_path


__all__ = ["app"]


if __name__ == "__main__":
    kwargs = {}
    pki_dir = get_pki_dir()
    if has_tls_material(pki_dir):
        kwargs["ssl_certfile"] = str(cert_path(pki_dir))
        kwargs["ssl_keyfile"] = str(key_path(pki_dir))
    uvicorn.run(app, host=get_host(), port=get_port(), **kwargs)
