import pytest
from app import app, FakeDB

@pytest.fixture
def client(monkeypatch):
    """
    Подменяем реальную БД на FakeDB,
    чтобы тесты не зависели от Mongo/Postgres.
    """
    fake_db = FakeDB()
    monkeypatch.setattr('app.db', fake_db)

    with app.test_client() as client:
        yield client


def test_api_create_book(client):
    """Создание книги через POST /api/books"""
    resp = client.post("/api/books", json={
        "title": "Book A",
        "author": "Author A",
        "year": 2024
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["title"] == "Book A"
    assert data["author"] == "Author A"


def test_api_get_books(client):
    """Проверяем, что список книг возвращается корректно"""
    client.post("/api/books", json={"title": "B1", "author": "A1"})
    client.post("/api/books", json={"title": "B2", "author": "A2"})

    resp = client.get("/api/books")
    assert resp.status_code == 200
    books = resp.get_json()
    assert len(books) == 2


def test_api_update_book(client):
    """Тест обновления книги"""
    create = client.post("/api/books", json={"title": "Old", "author": "A"})
    book_id = create.get_json()['id']

    resp = client.put(f"/api/books/{book_id}", json={"title": "New", "author": "A"})
    assert resp.status_code == 200
    assert resp.get_json()["title"] == "New"


def test_api_delete_book(client):
    """Удаление книги"""
    create = client.post("/api/books", json={"title": "Del", "author": "A"})
    book_id = create.get_json()['id']

    resp = client.delete(f"/api/books/{book_id}")
    assert resp.status_code == 200
    assert resp.get_json()["message"] == "Книга удалена"

    # после удаления книга не должна находиться
    resp2 = client.get(f"/api/books/{book_id}")
    assert resp2.status_code == 404
