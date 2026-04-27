"""HB_Zayfer Web Interface — FastAPI backend.

.. deprecated:: 1.1.1
    The FastAPI web backend is superseded by the Rust-native platform server
    (``hb-zayfer serve``). The Rust server is faster, ships in the default
    binary distribution, and shares its authentication and rate-limiting
    layers with the rest of the toolkit. The Python module is retained for
    backward compatibility only and will be removed in a future release.

    For new deployments, run::

        hb-zayfer serve --host 127.0.0.1 --port 8765

    A bearer token is generated automatically at startup (Jupyter-style); pass
    ``--no-auth`` only on a trusted loopback host.
"""

import warnings

from hb_zayfer.web.app import create_app, main

warnings.warn(
    "hb_zayfer.web (FastAPI) is deprecated; use the Rust-native server "
    "via 'hb-zayfer serve'. This module will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["create_app", "main"]
