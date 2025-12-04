import unittest
import json
from app import app, FakeDB

class TestAPI(unittest.TestCase):

    def setUp(self):
        # тестовый клиент Flask
        self.client = app.test_client()
        # очистим "базу"
        app.db.data = []

    def test_write_success(self):
        response = self.client.post("/write",
                                    data=json.dumps({"value": "hello"}),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ok", response.json["status"])
        self.assertEqual(app.db.data, ["hello"])

    def test_write_invalid_empty(self):
        response = self.client.post("/write",
                                    data=json.dumps({}),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_write_missing_field(self):
        response = self.client.post("/write",
                                    data=json.dumps({"wrong": 123}),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_db_stores_multiple_values(self):
        self.client.post("/write",
                         data=json.dumps({"value": "a"}),
                         content_type="application/json")
        self.client.post("/write",
                         data=json.dumps({"value": "b"}),
                         content_type="application/json")

        self.assertEqual(app.db.all(), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
