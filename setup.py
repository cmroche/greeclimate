import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="greeclimate",
    version="0.12.0",
    python_requires=">=3.6",
    install_requires=requirements,
    author="Clifford Roche",
    author_email="",
    description="Discover, connect and control Gree based minisplit systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cmroche/greeclimate",
    packages=setuptools.find_packages(exclude=["tests"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
)
