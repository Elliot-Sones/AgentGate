from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServiceDef:
    image: str
    default_env: dict[str, str] = field(default_factory=dict)
    ports: tuple[int, ...] = ()
    health_cmd: tuple[str, ...] = ()
    health_url: str = ""
    max_memory: str = "256m"
    ready_timeout_seconds: int = 45


ALLOWED_SERVICES: dict[str, ServiceDef] = {
    "postgres": ServiceDef(
        image="postgres:16-alpine",
        default_env={
            "POSTGRES_USER": "postgres",
            "POSTGRES_PASSWORD": "postgres",
            "POSTGRES_DB": "postgres",
        },
        ports=(5432,),
        health_cmd=("pg_isready", "-q", "-d", "postgres", "-U", "postgres"),
    ),
    "pgvector": ServiceDef(
        image="ankane/pgvector:v0.5.1",
        default_env={
            "POSTGRES_USER": "postgres",
            "POSTGRES_PASSWORD": "postgres",
            "POSTGRES_DB": "postgres",
        },
        ports=(5432,),
        health_cmd=("pg_isready", "-q", "-d", "postgres", "-U", "postgres"),
    ),
    "redis": ServiceDef(
        image="redis:7-alpine",
        ports=(6379,),
        health_cmd=("redis-cli", "ping"),
    ),
    "neo4j": ServiceDef(
        image="neo4j:5.26.4",
        default_env={
            "NEO4J_AUTH": "neo4j/mem0graph",
            "NEO4J_PLUGINS": '["apoc"]',
            "NEO4J_apoc_export_file_enabled": "true",
            "NEO4J_apoc_import_file_enabled": "true",
            "NEO4J_apoc_import_file_use__neo4j__config": "true",
        },
        ports=(7474, 7687),
        health_cmd=("wget", "--spider", "-q", "http://127.0.0.1:7474"),
        ready_timeout_seconds=120,
        max_memory="768m",
    ),
    "qdrant": ServiceDef(
        image="qdrant/qdrant:v1.9.0",
        ports=(6333,),
        health_cmd=("wget", "--spider", "-q", "http://127.0.0.1:6333/healthz"),
    ),
    "elasticsearch": ServiceDef(
        image="elasticsearch:8.13.0",
        default_env={
            "discovery.type": "single-node",
            "xpack.security.enabled": "false",
        },
        ports=(9200,),
        health_cmd=("wget", "--spider", "-q", "http://127.0.0.1:9200/_cluster/health"),
        ready_timeout_seconds=120,
        max_memory="1g",
    ),
    "mysql": ServiceDef(
        image="mysql:8.0",
        default_env={
            "MYSQL_ROOT_PASSWORD": "agentgate_test",
            "MYSQL_DATABASE": "app",
        },
        ports=(3306,),
        health_cmd=("mysqladmin", "ping", "-h", "127.0.0.1"),
        ready_timeout_seconds=90,
        max_memory="512m",
    ),
}
