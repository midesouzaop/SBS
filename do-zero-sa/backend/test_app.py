import io
import os
import tempfile
import unittest
from werkzeug.security import generate_password_hash

_TEST_DATA = tempfile.mkdtemp(prefix="do-zero-sa-test-")
os.environ["DATA_DIR"] = _TEST_DATA
os.environ["SECRET_KEY"] = "test-only-secret-not-for-production"
os.environ["ADMIN_USERNAME"] = "test-admin"
os.environ["ADMIN_PASSWORD_HASH"] = generate_password_hash("test-password")
os.environ["COOKIE_SECURE"] = "0"
os.environ["COOKIE_SAMESITE"] = "Lax"

from app import app  # noqa: E402


class DoZeroSaApiTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY=os.environ["SECRET_KEY"])
        self.client = app.test_client()
        self.csrf = None

    def login(self):
        response = self.client.post("/api/login", json={"username": "test-admin", "password": "test-password"})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.csrf = response.get_json()["csrfToken"]

    def test_health_is_public(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_assets_require_login(self):
        response = self.client.get("/api/assets")
        self.assertEqual(response.status_code, 401)

    def test_upload_and_delete_asset(self):
        self.login()
        response = self.client.post(
            "/api/assets",
            headers={"X-CSRF-Token": self.csrf},
            data={"files": (io.BytesIO(b"fake video bytes"), "lecture.mp4")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        asset_id = response.get_json()["items"][0]["id"]
        listed = self.client.get("/api/assets")
        self.assertEqual(len(listed.get_json()["items"]), 1)
        deleted = self.client.delete(f"/api/assets/{asset_id}", headers={"X-CSRF-Token": self.csrf})
        self.assertEqual(deleted.status_code, 200)

    def test_mutation_requires_csrf_token(self):
        self.login()
        response = self.client.post("/api/projects", json={
            "name": "Projeto de teste",
            "mode": "Aula original com capítulos e legendas",
        })
        self.assertEqual(response.status_code, 403)

    def test_create_project(self):
        self.login()
        response = self.client.post("/api/projects", headers={"X-CSRF-Token": self.csrf}, json={
            "name": "  Projeto   de teste  ",
            "mode": "Aula original com capítulos e legendas",
        })
        self.assertEqual(response.status_code, 201, response.get_json())
        self.assertEqual(response.get_json()["item"]["name"], "Projeto de teste")


if __name__ == "__main__":
    unittest.main()
