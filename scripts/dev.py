"""Makefile-like script for common development tasks."""

#!/usr/bin/env python3

import subprocess
import sys


def run(command: str) -> int:
    """Run a shell command and return exit code."""
    print(f"Running: {command}")
    return subprocess.call(command, shell=True)


def install():
    """Install the package in development mode."""
    return run("pip install -e '.[api,dev]'")


def test():
    """Run tests with coverage."""
    return run("pytest tests/ -v --cov=deployguard --cov-report=html --cov-report=term")


def test_unit():
    """Run only unit tests."""
    return run("pytest tests/unit/ -v -m unit")


def lint():
    """Run code quality checks."""
    commands = [
        "black --check deployguard/ tests/",
        "isort --check deployguard/ tests/",
        "flake8 deployguard/ tests/",
    ]
    for cmd in commands:
        if run(cmd) != 0:
            return 1
    return 0


def format_code():
    """Format code with black and isort."""
    run("black deployguard/ tests/")
    run("isort deployguard/ tests/")


def clean():
    """Clean build artifacts."""
    run("rm -rf build/ dist/ *.egg-info .pytest_cache/ htmlcov/ .coverage")
    run("find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true")


def build():
    """Build the package."""
    clean()
    return run("python setup.py sdist bdist_wheel")


def docker_build():
    """Build Docker image."""
    return run("docker-compose build")


def docker_up():
    """Start Docker containers."""
    return run("docker-compose up -d")


def docker_down():
    """Stop Docker containers."""
    return run("docker-compose down")


if __name__ == "__main__":
    commands = {
        "install": install,
        "test": test,
        "test-unit": test_unit,
        "lint": lint,
        "format": format_code,
        "clean": clean,
        "build": build,
        "docker-build": docker_build,
        "docker-up": docker_up,
        "docker-down": docker_down,
    }

    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print(f"Usage: python {sys.argv[0]} {{{','.join(commands.keys())}}}")
        sys.exit(1)

    sys.exit(commands[sys.argv[1]]())
