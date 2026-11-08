import os
import tempfile
import uuid

test_database = os.path.join(tempfile.gettempdir(), f"vigilante-test-{uuid.uuid4().hex}.db")
os.environ["DATABASE_URL"] = f"sqlite:///{test_database}"
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["WEBHOOK_SECRET"] = "test-webhook"
