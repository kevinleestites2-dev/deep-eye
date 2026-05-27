#!/usr/bin/env python3
"""
Setup script for Deep Eye
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="deep-eye",
    version="1.4.0",
    author="Deep Eye Security Team",
    author_email="security@deepeye.io",
    description="Advanced AI-Driven Penetration Testing Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zakirkun/deep-eye",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "deep-eye=deep_eye:main",
        ],
    },
    include_package_data=True,
    keywords="security penetration-testing vulnerability-scanner ai pentesting",
    project_urls={
        "Bug Reports": "https://github.com/zakirkun/deep-eye/issues",
        "Source": "https://github.com/zakirkun/deep-eye",
        "Documentation": "https://github.com/zakirkun/deep-eye/wiki",
    },
)
