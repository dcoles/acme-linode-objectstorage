from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name='acme-linode-objectstorage',
    version='0.1.0',
    description='ACME ("Let\'s Encrypt") client for Linode Object Storage',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/dcoles/acme-linode-objectstorage',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'requests',
        'cryptography',
    ],
)
