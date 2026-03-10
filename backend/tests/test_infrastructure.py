"""Tests for infrastructure - docker-compose, schema alignment, file integrity."""
import os
import re
import ast
import yaml
import pytest


PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


class TestDockerCompose:
    @pytest.fixture(autouse=True)
    def load_compose(self):
        with open(os.path.join(PROJECT_ROOT, "docker-compose.yml")) as f:
            self.compose = yaml.safe_load(f)

    def test_required_services_exist(self):
        required = ["postgres", "redis", "ollama", "backend", "celery_worker", "celery_beat", "nginx"]
        for svc in required:
            assert svc in self.compose["services"], f"Missing service: {svc}"

    def test_backend_depends_on_postgres(self):
        deps = self.compose["services"]["backend"].get("depends_on", {})
        assert "postgres" in deps or "postgres" in str(deps)

    def test_nginx_depends_on_backend(self):
        deps = self.compose["services"]["nginx"].get("depends_on", [])
        assert "backend" in deps or "backend" in str(deps)

    def test_volumes_defined(self):
        assert "pgdata" in self.compose.get("volumes", {})

    def test_auth_env_vars_in_backend(self):
        env = self.compose["services"]["backend"].get("environment", [])
        env_str = str(env)
        assert "AUTH_DISABLED" in env_str, "AUTH_DISABLED not passed to backend"
        assert "JWT_SECRET_KEY" in env_str, "JWT_SECRET_KEY not passed to backend"


class TestSchemaAlignment:
    def test_sql_tables_match_models(self):
        """Every SQL table must have a Python ORM model."""
        sql_dir = os.path.join(PROJECT_ROOT, "initdb")
        models_path = os.path.join(PROJECT_ROOT, "backend", "arguswatch", "models.py")

        sql_tables = set()
        for f in sorted(os.listdir(sql_dir)):
            if f.endswith(".sql"):
                content = open(os.path.join(sql_dir, f)).read()
                sql_tables.update(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)", content))

        models_content = open(models_path).read()
        py_tables = set(re.findall(r'__tablename__\s*=\s*"(\w+)"', models_content))

        missing = sql_tables - py_tables
        assert not missing, f"SQL tables without ORM models: {missing}"

    def test_models_parse_valid(self):
        models_path = os.path.join(PROJECT_ROOT, "backend", "arguswatch", "models.py")
        content = open(models_path).read()
        ast.parse(content)  # raises SyntaxError if invalid


class TestFileIntegrity:
    def test_all_python_files_parse(self):
        """Every .py file in backend/ must be valid Python."""
        backend = os.path.join(PROJECT_ROOT, "backend", "arguswatch")
        errors = []
        for root, dirs, files in os.walk(backend):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    try:
                        ast.parse(open(path).read())
                    except SyntaxError as e:
                        errors.append(f"{path}: {e}")
        assert not errors, f"Syntax errors in: {errors}"

    def test_requirements_has_auth_deps(self):
        reqs = open(os.path.join(PROJECT_ROOT, "backend", "requirements.txt")).read()
        assert "python-jose" in reqs, "Missing python-jose in requirements"
        assert "passlib" in reqs, "Missing passlib in requirements"
        assert "slowapi" in reqs, "Missing slowapi in requirements"

    def test_start_scripts_exist(self):
        for script in ["start.sh", "stop.sh", "fresh-start.sh"]:
            path = os.path.join(PROJECT_ROOT, script)
            assert os.path.exists(path), f"Missing {script}"
            assert os.access(path, os.X_OK), f"{script} not executable"

    def test_alembic_versions_exist(self):
        versions_dir = os.path.join(PROJECT_ROOT, "backend", "alembic", "versions")
        assert os.path.isdir(versions_dir), "alembic/versions/ directory missing"
        versions = [f for f in os.listdir(versions_dir) if f.endswith(".py")]
        assert len(versions) >= 2, f"Expected 2+ migration versions, found {len(versions)}"

    def test_nginx_config_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "nginx", "nginx.conf"))
        assert os.path.exists(os.path.join(PROJECT_ROOT, "nginx", "Dockerfile"))
