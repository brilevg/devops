import os
import time
import unittest
import psycopg2
from psycopg2 import OperationalError


class TestDatabaseConnection(unittest.TestCase):
    """Тест подключения к PostgreSQL через переменные окружения"""

    def test_connection(self):
        """Проверка подключения к PostgreSQL с повторными попытками"""
        
        # Получаем конфигурацию из переменных окружения
        db_config = {
            'host': os.environ.get('POSTGRES_HOST', 'localhost'),
            'port': os.environ.get('POSTGRES_PORT', '5432'),
            'database': os.environ.get('POSTGRES_DB')
            'user': os.environ.get('POSTGRES_USER')
            'password': os.environ.get('POSTGRES_PASSWORD')
        }
        
        print(f"Testing PostgreSQL connection with config: {db_config}")
        
        # Проверяем обязательные поля (без пароля для логирования)
        safe_config = db_config.copy()
        safe_config['password'] = '[REDACTED]' if db_config['password'] else '[MISSING]'
        print(f"Database config: {safe_config}")
        
        max_retries = 10
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                print(f"Connection attempt {attempt + 1}/{max_retries}...")
                
                # Используем 'database' (работает в psycopg2)
                conn = psycopg2.connect(
                    host=db_config['host'],
                    port=db_config['port'],
                    database=db_config['database'],
                    user=db_config['user'],
                    password=db_config['password']
                )
                
                # Проверяем соединение
                with conn.cursor() as cursor:
                    cursor.execute("SELECT version()")
                    version = cursor.fetchone()[0]
                    print(f"✅ Connected to PostgreSQL: {version.split(',')[0]}")
                    
                    # Выполняем тестовый запрос
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    print(f"Test query result: {result[0]}")
                
                conn.close()
                return  # Успех — тест пройден
                
            except OperationalError as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
        
        self.fail(f"Failed to connect to PostgreSQL after {max_retries} attempts")


if __name__ == "__main__":
    # УБЕРИТЕ sys.exit(0) отсюда!
    # unittest.main() сам управляет кодом выхода
    unittest.main(verbosity=2)
    
    # Или, если хотите явный код выхода:
    # result = unittest.main(exit=False)
    # sys.exit(0 if result.result.wasSuccessful() else 1)
