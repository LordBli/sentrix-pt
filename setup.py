from setuptools import setup, find_packages

setup(
    name="sentrix-pt",
    version="0.1.0",
    description="AI Penetration Testing Framework — by SENTRIX",
    author="SENTRIX AI Security Agency",
    url="https://github.com/LordBli/sentrix-pt",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "httpx>=0.27.0",
        "pydantic>=2.0.0",
        "reportlab>=4.0.0",
        "jinja2>=3.1.0",
        "python-dotenv>=1.0.0",
        "PyYAML>=6.0.0",
    ],
    entry_points={
        "console_scripts": [
            "sentrix-pt=sentrix_pt.cli:main",
        ],
    },
)
