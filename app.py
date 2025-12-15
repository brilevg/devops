from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import time
from datetime import datetime
from bson.objectid import ObjectId
from bson.errors import InvalidId


app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Определяем тип БД из переменных окружения
DB_TYPE = os.getenv('DB_TYPE').lower()

print(f"Запуск сервера с БД: {DB_TYPE}")


class FakeDB:
    def __init__(self):
        self.books = []
        self.next_id = 1
        print("FakeDB работает")
    
    def get_all_books(self):
        return self.books.copy()
    
    def get_book(self, book_id):
        try:
            book_id = int(book_id)
        except Exception:
            return None
            
        for book in self.books:
            if book['id'] == book_id:
                return book
        return None
    
    def create_book(self, book_data):
        book = {
            'id': self.next_id,
            'title': book_data['title'],
            'author': book_data['author'],
            'year': book_data.get('year'),
            'description': book_data.get('description', ''),
            'created_at': datetime.now().isoformat()
        }
        self.books.append(book)
        self.next_id += 1
        return book
    
    def update_book(self, book_id, book_data):
        try:
            book_id = int(book_id)
        except Exception:
            return None
            
        for book in self.books:
            if book['id'] == book_id:
                book.update({
                    'title': book_data['title'],
                    'author': book_data['author'],
                    'year': book_data.get('year'),
                    'description': book_data.get('description', ''),
                    'updated_at': datetime.now().isoformat()
                })
                return book
        return None
    
    def delete_book(self, book_id):
        try:
            book_id = int(book_id)
        except Exception:
            return None
            
        for i, book in enumerate(self.books):
            if book['id'] == book_id:
                return self.books.pop(i)
        return None


class PostgresDB:
    def __init__(self):
        import psycopg2
        max_retries = 10
        for i in range(max_retries):
            try:
                self.conn = psycopg2.connect(
                    host=os.getenv('POSTGRES_HOST'),
                    port=os.getenv('POSTGRES_PORT'),
                    database=os.getenv('POSTGRES_DB'),
                    user=os.getenv('POSTGRES_USER'),
                    password=os.getenv('POSTGRES_PASSWORD')
                )
                print("PostgreSQL подключена")
                self._init_db()
                return
            except Exception as e:
                print(f"PostgreSQL загружается {e}")
                if i < max_retries - 1:
                    time.sleep(2)
        raise Exception("PostgreSQL не подключилась")
    
    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id SERIAL PRIMARY KEY,
                title VARCHAR(500) NOT NULL,
                author VARCHAR(255) NOT NULL,
                year INTEGER,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
        cur.close()
    
    def get_all_books(self):
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM books ORDER BY id')
        books = []
        for row in cur.fetchall():
            books.append({
                'id': row[0],
                'title': row[1],
                'author': row[2],
                'year': row[3],
                'description': row[4],
                'created_at': row[5].isoformat() if row[5] else None,
                'updated_at': row[6].isoformat() if row[6] else None
            })
        cur.close()
        return books
    
    def get_book(self, book_id):
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM books WHERE id = %s', (book_id,))
        row = cur.fetchone()
        cur.close()
        if row:
            return {
                'id': row[0],
                'title': row[1],
                'author': row[2],
                'year': row[3],
                'description': row[4],
                'created_at': row[5].isoformat() if row[5] else None,
                'updated_at': row[6].isoformat() if row[6] else None
            }
        return None
    
    def create_book(self, book_data):
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO books (title, author, year, description) VALUES (%s, %s, %s, %s) RETURNING id',
            (book_data['title'], book_data['author'], book_data.get('year'), book_data.get('description', ''))
        )
        book_id = cur.fetchone()[0]
        self.conn.commit()
        cur.close()
        return self.get_book(book_id)
    
    def update_book(self, book_id, book_data):
        cur = self.conn.cursor()
        cur.execute(
            'UPDATE books SET title = %s, author = %s, year = %s, description = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
            (book_data['title'], book_data['author'], book_data.get('year'), book_data.get('description', ''), book_id)
        )
        self.conn.commit()
        cur.close()
        return self.get_book(book_id)
    
    def delete_book(self, book_id):
        book = self.get_book(book_id)
        if book:
            cur = self.conn.cursor()
            cur.execute('DELETE FROM books WHERE id = %s', (book_id,))
            self.conn.commit()
            cur.close()
        return book


class MongoDB:
    def __init__(self):
        from pymongo import MongoClient
        max_retries = 10
        for i in range(max_retries):
            try:
                self.client = MongoClient(
                    host=os.getenv('MONGO_HOST'),
                    port=int(os.getenv('MONGO_PORT')),
                    serverSelectionTimeoutMS=5000
                )
                # Проверяем соединение
                self.client.admin.command('ping')
                self.db = self.client[os.getenv('MONGO_DB')]
                self.books = self.db.books
                print("MongoDB подключена")
                return
            except Exception as e:
                print(f"MongoDB запускается {e}")
                if i < max_retries - 1:
                    time.sleep(2)
        raise Exception("MongoDB не запустилась")
    
    def get_all_books(self):
        try:
            books_cursor = self.books.find().sort('_id', 1)
            books = []
            for book in books_cursor:
                book_data = {
                    'id': str(book['_id']),
                    'title': book['title'],
                    'author': book['author'],
                    'year': book.get('year'),
                    'description': book.get('description', '')
                }
                if 'created_at' in book:
                    book_data['created_at'] = book['created_at'].isoformat() if isinstance(book['created_at'], datetime) else str(book['created_at'])
                if 'updated_at' in book:
                    book_data['updated_at'] = book['updated_at'].isoformat() if isinstance(book['updated_at'], datetime) else str(book['updated_at'])
                
                books.append(book_data)
            return books
        except Exception as e:
            print(f"Ошибка: {e}")
            return []
    
    def get_book(self, book_id):
        try:
            book = self.books.find_one({'_id': ObjectId(book_id)})
            if book:
                book_data = {
                    'id': str(book['_id']),
                    'title': book['title'],
                    'author': book['author'],
                    'year': book.get('year'),
                    'description': book.get('description', '')
                }
                if 'created_at' in book:
                    book_data['created_at'] = book['created_at'].isoformat() if isinstance(book['created_at'], datetime) else str(book['created_at'])
                if 'updated_at' in book:
                    book_data['updated_at'] = book['updated_at'].isoformat() if isinstance(book['updated_at'], datetime) else str(book['updated_at'])
                
                return book_data
            return None
        except (InvalidId, Exception) as e:
            print(f"Ошибка: {e}")
            return None
    
    def create_book(self, book_data):
        try:
            book_doc = {
                'title': book_data['title'],
                'author': book_data['author'],
                'year': book_data.get('year'),
                'description': book_data.get('description', ''),
                'created_at': datetime.now()
            }
            result = self.books.insert_one(book_doc)
            return self.get_book(result.inserted_id)
        except Exception as e:
            print(f"Ошибка: {e}")
            return None
    
    def update_book(self, book_id, book_data):
        try:
            update_data = {
                'title': book_data['title'],
                'author': book_data['author'],
                'year': book_data.get('year'),
                'description': book_data.get('description', ''),
                'updated_at': datetime.now()
            }
            
            # Удаляем None значения
            update_data = {k: v for k, v in update_data.items() if v is not None}
            
            result = self.books.update_one(
                {'_id': ObjectId(book_id)},
                {'$set': update_data}
            )
            if result.modified_count == 1:
                return self.get_book(book_id)
            else:
                print(f"Книга не найдена: {book_id}")
                return None
        except (InvalidId, Exception) as e:
            print(f"Ошибка: {e}")
            return None
    
    def delete_book(self, book_id):
        try:
            book = self.get_book(book_id)
            if book:
                result = self.books.delete_one({'_id': ObjectId(book_id)})
                if result.deleted_count == 1:
                    return book
                else:
                    print(f"Книга не удалена: {book_id}")
                    return None
            return None
        except (InvalidId, Exception) as e:
            print(f"Ошибка: {e}")
            return None

# Инициализация БД
def get_db():
    if DB_TYPE == 'postgres':
        return PostgresDB()
    elif DB_TYPE == 'mongo':
        return MongoDB()
    else:
        return FakeDB()


db = get_db()

# HTML
@app.route('/')
def index():
    return redirect(url_for('book_list'))


@app.route('/books')
def book_list():
    try:
        books = db.get_all_books()
        return render_template('book_list.html', books=books, db_type=DB_TYPE)
    except Exception as e:
        flash(f'Ошибка загрузки книг: {str(e)}', 'error')
        return render_template('book_list.html', books=[], db_type=DB_TYPE)


@app.route('/books/create', methods=['GET', 'POST'])
def book_create():
    if request.method == 'POST':
        try:
            book_data = {
                'title': request.form['title'],
                'author': request.form['author'],
                'year': int(request.form['year']) if request.form['year'] else None,
                'description': request.form['description']
            }
            
            book = db.create_book(book_data)
            if book:
                flash(f'Книга "{book["title"]}" успешно добавлена в {DB_TYPE.upper()}!', 'success')
            else:
                flash('Ошибка при создании книги', 'error')
            return redirect(url_for('book_list'))
        except Exception as e:
            flash(f'Ошибка при создании книги: {str(e)}', 'error')
            return redirect(url_for('book_list'))
    
    return render_template('book_form.html', db_type=DB_TYPE)


@app.route('/books/<book_id>/edit', methods=['GET', 'POST'])
def book_edit(book_id):
    if request.method == 'POST':
        try:
            book_data = {
                'title': request.form['title'],
                'author': request.form['author'],
                'year': int(request.form['year']) if request.form['year'] else None,
                'description': request.form['description']
            }
            
            book = db.update_book(book_id, book_data)
            if book:
                flash(f'Книга "{book["title"]}" успешно обновлена в {DB_TYPE.upper()}!', 'success')
            else:
                flash('Книга не найдена', 'error')
            return redirect(url_for('book_list'))
        except Exception as e:
            flash(f'Ошибка при обновлении книги: {str(e)}', 'error')
            return redirect(url_for('book_list'))
    
    book = db.get_book(book_id)
    if not book:
        flash('Книга не найдена', 'error')
        return redirect(url_for('book_list'))
    
    return render_template('book_form.html', book=book, db_type=DB_TYPE)


@app.route('/books/<book_id>/delete', methods=['POST'])
def book_delete(book_id):
    try:
        book = db.delete_book(book_id)
        if book:
            flash(f'Книга "{book["title"]}" успешно удалена из {DB_TYPE.upper()}!', 'success')
        else:
            flash('Книга не найдена', 'error')
    except Exception as e:
        flash(f'Ошибка при удалении книги: {str(e)}', 'error')
    return redirect(url_for('book_list'))

# API
@app.route('/api/books', methods=['GET'])
def api_get_books():
    try:
        books = db.get_all_books()
        return jsonify(books)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/books/<book_id>', methods=['GET'])
def api_get_book(book_id):
    try:
        book = db.get_book(book_id)
        if book:
            return jsonify(book)
        return jsonify({'error': 'Книга не найдена'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/books', methods=['POST'])
def api_create_book():
    try:
        data = request.get_json()
        if not data or 'title' not in data or 'author' not in data:
            return jsonify({'error': 'Автор и название обязательны'}), 400
        
        book = db.create_book(data)
        if book:
            return jsonify(book), 201
        else:
            return jsonify({'error': 'Книга не создалась'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books/<book_id>', methods=['PUT'])
def api_update_book(book_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Нет данных'}), 400
        
        book = db.update_book(book_id, data)
        if book:
            return jsonify(book)
        return jsonify({'error': 'Книга не найдена'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books/<book_id>', methods=['DELETE'])
def api_delete_book(book_id):
    try:
        book = db.delete_book(book_id)
        if book:
            return jsonify({'message': 'Книга удалена'})
        return jsonify({'error': 'Книга не найдена'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/db_info')
def api_db_info():
    try:
        books = db.get_all_books()
        return jsonify({
            'db_type': DB_TYPE,
            'books_count': len(books)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
