def exploit(url, param):
    return {
        "url": url,
        "dbms": "MySQL",
        "database": "users_db",
        "tables": ["users", "orders"],
        "sample_data": {"users": [{"id": 1, "username": "admin"}]}
    }
