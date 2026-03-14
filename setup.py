from setuptools import setup, find_packages

setup(
    name="spploginmaster",
    version="1.0.0",
    description="Secure Privacy Protection Login Master - Fingerprint/password app encryption for Linux",
    author="SPPLoginMaster Contributors",
    license="GPL-3.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "PyGObject>=3.42",
    ],
    entry_points={
        "console_scripts": [
            "spp-cli=spp.cli:main",
        ],
        "gui_scripts": [
            "spp-gui=spp.gui:main",
        ],
    },
)
