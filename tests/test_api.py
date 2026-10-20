import unittest

from app import create_app
from models import Note, User, db


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "JWT_SECRET_KEY": "test-secret-key-long-enough-for-automated-tests",
            }
        )

        with cls.app.app_context():
            user = User(login="student")
            user.set_password("SafePass123!")
            db.session.add(user)
            db.session.commit()

        cls.client = cls.app.test_client()
        login = cls.client.post(
            "/auth/login",
            json={"login": "student", "password": "SafePass123!"},
        )
        token = login.get_json()["access_token"]
        cls.auth_headers = {"Authorization": f"Bearer {token}"}

    def test_login_returns_jwt(self):
        response = self.client.post(
            "/auth/login",
            json={"login": "student", "password": "SafePass123!"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["access_token"])
        self.assertEqual(response.get_json()["user"]["login"], "student")

    def test_password_is_stored_as_a_hash(self):
        with self.app.app_context():
            user = db.session.scalar(
                db.select(User).where(User.login == "student")
            )
            self.assertNotEqual(user.password_hash, "SafePass123!")
            self.assertTrue(user.password_hash.startswith("$2"))

    def test_invalid_credentials_use_same_error(self):
        wrong_password = self.client.post(
            "/auth/login",
            json={"login": "student", "password": "wrong-password"},
        )
        unknown_user = self.client.post(
            "/auth/login",
            json={"login": "unknown", "password": "wrong-password"},
        )
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(unknown_user.status_code, 401)
        self.assertEqual(wrong_password.get_json(), unknown_user.get_json())

    def test_sql_injection_login_is_rejected(self):
        response = self.client.post(
            "/auth/login",
            json={"login": "' OR 1=1--", "password": "anything"},
        )
        self.assertEqual(response.status_code, 401)

    def test_protected_data_requires_a_token(self):
        response = self.client.get("/api/data")
        self.assertEqual(response.status_code, 401)

    def test_protected_data_accepts_a_valid_token(self):
        response = self.client.get("/api/data", headers=self.auth_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user"]["login"], "student")

    def test_note_escapes_xss_before_storage(self):
        response = self.client.post(
            "/api/notes",
            json={"content": '<script>alert("XSS")</script>Hello'},
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 201)
        safe_content = response.get_json()["note"]["content"]
        self.assertNotIn("<script>", safe_content)
        self.assertIn("&lt;script&gt;", safe_content)

        with self.app.app_context():
            saved_note = db.session.scalar(db.select(Note))
            self.assertEqual(saved_note.content, safe_content)

    def test_note_rejects_empty_content(self):
        response = self.client.post(
            "/api/notes",
            json={"content": "   "},
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
