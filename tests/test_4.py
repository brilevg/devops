#!/usr/bin/env python3
import os
import sys
import psycopg2

# Простейший тест
try:
    conn = psycopg2.connect(
        host="localhost",
        port="5432",
        database="db",
        user="user",
        password="password"
    )
    print("✅ SUCCESS: Connected to PostgreSQL")
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f"❌ FAILED: {e}")
    sys.exit(1)
