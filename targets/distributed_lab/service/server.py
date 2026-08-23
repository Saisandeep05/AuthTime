"""
AuthTime Distributed Lab - Replica Server Launcher.
Invoked by command line or Docker container to run API-1, API-2, or API-3.
"""

import os
import sys
import uvicorn

from targets.distributed_lab.db.database import LabDatabase
from targets.distributed_lab.cache.redis_cache import LabRedisCache
from targets.distributed_lab.auth.jwt_handler import LabJWTHandler
from targets.distributed_lab.service.app import create_lab_replica_app

# Shared in-memory instances for single-process multi-replica deployment
shared_db = LabDatabase()
shared_cache = LabRedisCache()
shared_jwt = LabJWTHandler()


def main():
    replica_id = os.getenv("REPLICA_ID", "api-1")
    port = int(os.getenv("PORT", "8010"))
    host = os.getenv("HOST", "127.0.0.1")

    app = create_lab_replica_app(
        replica_id=replica_id,
        db=shared_db,
        cache=shared_cache,
        jwt_handler=shared_jwt,
    )
    print(f"[*] AuthTime Distributed Lab API Replica [{replica_id}] starting on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
