from setuptools import setup, find_packages

setup(
    name="packetguard",
    version="1.0.0",
    description="Lightweight Open-Source Package Supply Chain Security Threat Detection Engine",
    long_description="PacketGuard - 轻量级开源包供应链安全威胁检测引擎",
    author="PacketGuard Team",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    package_data={
        "packetguard": ["data/*.json"],
    },
    entry_points={
        "console_scripts": [
            "packetguard=packetguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
