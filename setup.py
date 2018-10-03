"""Setup configuration for the `bscan` program."""

import codes
import os

from setuptools import (
    find_packages,
    setup)

HERE = os.path.abspath(os.path.dirname(__file__))
README_FILE = os.path.join(HERE, 'README.rst')
REQS_FILE = os.path.join(HERE, 'requirements.txt')
BSCAN_DIR = os.path.join(HERE, 'bscan')
VERSION_FILE = os.path.join(BSCAN_DIR, 'version.py')

with codes.open(VERSION_FILE, encoding='utf-8') as f:
    exec(f.read())
    version = __version__  # noqa

with codes.open(README_FILE, encoding='utf-8') as f:
    long_desc = f.read()

with codes.open(REQS_FILE, encoding='utf-8') as f:
    install_requires = [line.strip() for line in f if line.strip()]

setup(
    name='bscan',
    version=version,
    description='An asynchronous target scanner',
    author='Brian Welch',
    author_email='welch18@vt.edu',
    url='https://github.com/welchbj/bscan',
    license='MIT',
    install_requires=['colorama', 'toml'],
    packages=find_packages(exclude=['tests', '*.tests', '*.tests.*']),
    entry_points={
        'console_scripts': ['bscan = bscan.__main__:main']
    },
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.6',
        'Topic :: Utilities'
    ])
