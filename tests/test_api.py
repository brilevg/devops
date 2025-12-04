import unittest
import json
from app import app, FakeDB,

class TestFakeDB(unittest.TestCase):
    def setUp(self):
        self.db = FakeDB()

    def test_create_and_get_book(self):
        book_data = {'title': 'Test', 'author': 'Author', 'year': 2023}
        book = self.db.create_book(book_data)
        self.assertEqual(book['id'], 1)
        self.assertEqual(book['title'], 'Test')

        fetched = self.db.get_book(1)
        self.assertEqual(fetched['title'], 'Test')

    def test_update_book(self):
        book = self.db.create_book({'title': 'A', 'author': 'B'})
        updated = self.db.update_book(1, {'title': 'C', 'author': 'D'})
        self.assertEqual(updated['title'], 'C')
        self.assertEqual(updated['author'], 'D')

    def test_delete_book(self):
        book = self.db.create_book({'title': 'A', 'author': 'B'})
        deleted = self.db.delete_book(1)
        self.assertEqual(deleted['title'], 'A')
        self.assertIsNone(self.db.get_book(1))

class TestAPI(unittest.TestCase):
    def setUp(self):
        # Тестовый клиент Flask
        self.app = app.test_client()

        # Сохраняем реальный db и подменяем на FakeDB
        global db
        self.original_db = db
        db = FakeDB()

    def tearDown(self):
        global db
        # Восстанавливаем оригинальный db
        db = self.original_db

    def test_api_create_book(self):
        response = self.app.post('/api/books', json={
            'title': 'API Book',
            'author': 'API Author',
            'year': 2025
        })
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data['title'], 'API Book')
        self.assertEqual(len(db.get_all_books()), 1)

    def test_api_get_books(self):
        db.create_book({'title': 'B1', 'author': 'A1'})
        db.create_book({'title': 'B2', 'author': 'A2'})
        response = self.app.get('/api/books')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data), 2)

    def test_api_get_single_book(self):
        book = db.create_book({'title': 'Single', 'author': 'One'})
        response = self.app.get(f'/api/books/{book["id"]}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['title'], 'Single')

    def test_api_update_book(self):
        book = db.create_book({'title': 'Old', 'author': 'Old'})
        response = self.app.put(f'/api/books/{book["id"]}', json={'title': 'New', 'author': 'New'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['title'], 'New')

    def test_api_delete_book(self):
        book = db.create_book({'title': 'Del', 'author': 'Del'})
        response = self.app.delete(f'/api/books/{book["id"]}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['message'], 'Книга удалена')
        self.assertEqual(len(db.get_all_books()), 0)

if __name__ == '__main__':
    unittest.main()
