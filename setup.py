from setuptools import setup, find_packages

setup(
    name="bitsafe-utils",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "fastapi",
        "uvicorn",
        "pydantic",
        "pytest",
    ],
    python_requires=">=3.8",
)
