"""Setup configuration for the `bscan` program."""

import codecs
import os

from setuptools import (
    find_packages,
    setup)

HERE = os.path.abspath(os.path.dirname(__file__))
BSCAN_DIR = os.path.join(HERE, 'bscan')
VERSION_FILE = os.path.join(BSCAN_DIR, 'version.py')

with codecs.open(VERSION_FILE, encoding='utf-8') as f:
    exec(f.read())
    version = __version__  # noqa

setup(
    name='bscan',
    version=version,
    description='An asynchronous target scanner',
    long_description='Visit the project\'s home page for more information',
    author='Brian Welch',
    author_email='welch18@vt.edu',
    url='https://github.com/welchbj/bscan',
    license='MIT',
    install_requires=['colorama', 'sublemon', 'toml'],
    packages=find_packages(exclude=['tests', '*.tests', '*.tests.*']),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'bscan = bscan.__main__:main',
            'bscan-wordlists = bscan.__main__:wordlists_main'
        ]
    },
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.6',
        'Topic :: Utilities'
    ]
)
