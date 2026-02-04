"""Setup configuration for DeployGuard Repository Cleaner."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="deployguard-repo-guard",
    version="0.1.0",
    author="DeployGuard Team",
    author_email="team@deployguard.net",
    description="Automatically detect, remove, and manage exposed secrets in Git repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/salginci/deployguard_repository_cleaner",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Version Control :: Git",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.0",
        "gitpython>=3.1.40",
        "PyGithub>=2.1.1",
        "atlassian-python-api>=3.41.0",
        "detect-secrets>=1.4.0",
        "pyyaml>=6.0",
        "cryptography>=41.0.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "deployguard=deployguard.cli.main:cli",
        ],
    },
    extras_require={
        "api": [
            "fastapi>=0.109.0",
            "uvicorn[standard]>=0.27.0",
            "sqlalchemy>=2.0.25",
            "alembic>=1.13.0",
            "psycopg2-binary>=2.9.9",
            "redis>=5.0.1",
            "celery>=5.3.4",
            "python-jose[cryptography]>=3.3.0",
            "passlib[bcrypt]>=1.7.4",
            "python-multipart>=0.0.6",
        ],
        "dev": [
            "pytest>=7.4.4",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.23.3",
            "pytest-mock>=3.12.0",
            "black>=24.1.0",
            "isort>=5.13.2",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
            "pre-commit>=3.6.0",
            "httpx>=0.26.0",
        ],
    },
    include_package_data=True,
    package_data={
        "deployguard": [
            "config/*.yaml",
            "config/*.yml",
        ],
    },
)
