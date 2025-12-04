import unittest
from app import app, FakeDB

class TestFakeDB(unittest.TestCase):
    def setUp(self):
        self.db = FakeDB()

    def test_create_and_get_book(self):
        book_data = {'title': 'Book 1', 'author': 'Author 1'}
        book = self.db.create_book(book_data)
        self.assertIsNotNone(book)
        self.assertEqual(book['title'], 'Book 1')
        self.assertEqual(book['author'], 'Author 1')

        fetched = self.db.get_book(book['id'])
        self.assertEqual(fetched, book)

    def test_update_book(self):
        book = self.db.create_book({'title': 'Book 1', 'author': 'Author 1'})
        updated = self.db.update_book(book['id'], {'title': 'Updated', 'author': 'Author 2'})
        self.assertEqual(updated['title'], 'Updated')
        self.assertEqual(updated['author'], 'Author 2')

    def test_delete_book(self):
        book = self.db.create_book({'title': 'Book 1', 'author': 'Author 1'})
        deleted = self.db.delete_book(book['id'])
        self.assertEqual(deleted, book)
        self.assertIsNone(self.db.get_book(book['id']))

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

        # Подменяем db на FakeDB
        self.original_db = app.view_functions['api_get_books'].__globals__['db']
        app.view_functions['api_get_books'].__globals__['db'] = FakeDB()

        # Тоже подменяем для всех view functions
        for key, view in app.view_functions.items():
            if 'db' in view.__globals__:
                view.__globals__['db'] = app.view_functions['api_get_books'].__globals__['db']

        self.db = app.view_functions['api_get_books'].__globals__['db']

    def tearDown(self):
        # Возвращаем оригинальный db
        for key, view in app.view_functions.items():
            if 'db' in view.__globals__:
                view.__globals__['db'] = self.original_db

    def test_api_create_book(self):
        response = self.client.post('/api/books', json={'title': 'Book A', 'author': 'Author A'})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(self.db.get_all_books()), 1)

    def test_api_get_books(self):
        self.db.create_book({'title': 'Book 1', 'author': 'Author 1'})
        self.db.create_book({'title': 'Book 2', 'author': 'Author 2'})
        response = self.client.get('/api/books')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data), 2)

    def test_api_get_single_book(self):
        book = self.db.create_book({'title': 'Book X', 'author': 'Author X'})
        response = self.client.get(f'/api/books/{book["id"]}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['title'], 'Book X')

    def test_api_update_book(self):
        book = self.db.create_book({'title': 'Book Old', 'author': 'Author Old'})
        response = self.client.put(f'/api/books/{book["id"]}', json={'title': 'Book New', 'author': 'Author New'})
        self.assertEqual(response.status_code, 200)
        updated = self.db.get_book(book['id'])
        self.assertEqual(updated['title'], 'Book New')

    def test_api_delete_book(self):
        book = self.db.create_book({'title': 'Book Del', 'author': 'Author Del'})
        response = self.client.delete(f'/api/books/{book["id"]}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.db.get_all_books()), 0)

if __name__ == '__main__':
    unittest.main()
