import os
import time
import unittest
import psycopg2
from psycopg2 import OperationalError


class TestDatabaseConnection(unittest.TestCase):
    """Тест подключения к PostgreSQL через переменные окружения"""

    def test_connection(self):
        """Проверка подключения к PostgreSQL"""
        
        # Получаем значения переменных окружения
        db_config = {
            'host': os.getenv('POSTGRES_HOST', 'localhost'),
            'port': os.getenv('POSTGRES_PORT', '5432'),
            'database': os.getenv('POSTGRES_DB'),
            'user': os.getenv('POSTGRES_USER'),
            'password': os.getenv('POSTGRES_PASSWORD')
        }
        
        # Отладочная информация
        print(f"Конфигурация БД: {db_config}")
        
        # Проверяем, что обязательные переменные установлены
        if not all([db_config['database'], db_config['user'], db_config['password']]):
            self.fail("Не все обязательные переменные окружения установлены: "
                     "POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD")
        
        # Увеличиваем количество попыток для CI/CD
        max_retries = 30  # Увеличиваем до 30 попыток для GitHub Actions
        retry_delay = 2   # 2 секунды между попытками
        
        for i in range(max_retries):
            try:
                print(f"Попытка подключения {i+1}/{max_retries}...")
                
                # Параметр 'database' работает в psycopg2 (это синоним для 'dbname')
                self.conn = psycopg2.connect(
                    host=db_config['host'],
                    port=db_config['port'],
                    database=db_config['database'],  # Используем 'database' вместо 'dbname'
                    user=db_config['user'],
                    password=db_config['password']
                )
                
                # Проверяем, что соединение действительно работает
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    print(f"✅ PostgreSQL подключена! Результат запроса: {result[0]}")
                
                self.conn.close()
                return  # Успех → тест пройден
                
            except OperationalError as e:
                print(f"PostgreSQL загружается... {e}")
                if i < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    print(f"❌ Все {max_retries} попыток неудачны")
        
        self.fail("Не удалось подключиться к PostgreSQL через переменные окружения")


if __name__ == "__main__":
    unittest.main(verbosity=2)
