"""
Setup script for MAESTRO Threat Assessment Framework
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="maestro-threat-assessment",
    version="1.0.0",
    author="MAESTRO Security Team",
    author_email="security@maestro.ai",
    description="Comprehensive security risk assessment for agentic workflows using MAESTRO framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/maestro-security/threat-assessment",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=22.0",
            "flake8>=5.0",
            "mypy>=1.0",
        ],
        "web": [
            "flask>=3.0.0",
            "gunicorn>=21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "maestro=maestro_threat_assessment.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "maestro_threat_assessment": [
            "examples/*.yaml",
            "templates/*.html",
        ],
    },
    keywords="security, risk-assessment, ai, agents, threat-modeling, maestro, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/maestro-security/threat-assessment/issues",
        "Source": "https://github.com/maestro-security/threat-assessment",
        "Documentation": "https://maestro-security.github.io/threat-assessment/",
    },
)
