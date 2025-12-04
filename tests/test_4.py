import os
import time
import unittest
import psycopg2


class TestDatabaseConnection(unittest.TestCase):

    def test_connection(self):

        cfg = {
            "host": os.environ.get("POSTGRES_HOST", "localhost"),
            "port": os.environ.get("POSTGRES_PORT", 5432),
            "dbname": os.environ["POSTGRES_NAME"],
            "user": os.environ["POSTGRES_USER"],
            "password": os.environ["POSTGRES_PASSWORD"],
        }

        # даём PostgreSQL время подняться
        for _ in range(10):
            try:
                conn = psycopg2.connect(**cfg)
                conn.close()
                return  # Успех → тест пройден
            except Exception:
                time.sleep(1)

        self.fail("Не удалось подключиться к PostgreSQL через переменные окружения")


if __name__ == "__main__":
    unittest.main()
