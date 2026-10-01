from __future__ import annotations

from mangum import Mangum

from vaultrag.api.app import create_app

app = create_app()
handler = Mangum(app, lifespan="off")
