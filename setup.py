from setuptools import find_packages, setup


setup(
    name="mcpsentinel",
    version="1.0",
    packages=find_packages(),
    py_modules=["cli"],
    install_requires=[
        "requests",
        "google-genai",
    ],
    entry_points={
        "console_scripts": [
            "mcpsentinel=cli:main",
        ]
    },
)
