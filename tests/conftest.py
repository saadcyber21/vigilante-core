import os
os.environ["DATABASE_URL"] = "sqlite:///./test-vigilante.db"
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["WEBHOOK_SECRET"] = "test-webhook"
