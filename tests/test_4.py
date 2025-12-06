import os
import time
import unittest
import psycopg2


class TestDatabaseConnection(unittest.TestCase):

    def test_connection(self):

        cfg = {
            "host": os.getenv("POSTGRES_HOST"),
            "port": os.getenv("POSTGRES_PORT"),
            "dbname": os.getenv("POSTGRES_DB"),
            "user": os.getenv("POSTGRES_USER"),
            "password": os.getenv("POSTGRES_PASSWORD"),
        }
        print(cfg)

        # даём PostgreSQL время подняться
        for _ in range(10):
            try:
                conn = sycopg2.connect(
                    host=os.getenv('POSTGRES_HOST'),
                    port=os.getenv('POSTGRES_PORT'),
                    database=os.getenv('POSTGRES_DB'),
                    user=os.getenv('POSTGRES_USER'),
                    password=os.getenv('POSTGRES_PASSWORD')
                )
                conn.close()
                return 1 # Успех → тест пройден
            except Exception:
                time.sleep(1)

        self.fail("Не удалось подключиться к PostgreSQL через переменные окружения")


if __name__ == "__main__":
    unittest.main()
