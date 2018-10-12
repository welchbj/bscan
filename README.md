# ![bscan](https://raw.githubusercontent.com/welchbj/bscan/master/static/logo.png)

[![Travis Status](https://img.shields.io/travis/welchbj/bscan/master.svg?style=flat-square&label=travis)](https://travis-ci.org/welchbj/bscan) [![PyPI](https://img.shields.io/pypi/v/bscan.svg?style=flat-square&label=pypi)](https://pypi.org/project/bscan/) [![Python Versions](https://img.shields.io/badge/python-3.6-c944ff.svg?style=flat-square)](https://pypi.org/project/bscan/) [![Built for Kali](https://img.shields.io/badge/built%20for-kali-2a98ed.svg?style=flat-square)](https://www.kali.org/)

An asynchronous network scanning, enumeration, and recommendation tool.

<a href="https://asciinema.org/a/205992?autoplay=1&speed=3"><img src="https://asciinema.org/a/205992.png" width="544"/></a>


## Installation

Download the latest packaged version from PyPI:
```sh
pip install bscan
```

Or get the bleeding-edge version from version control:
```sh
pip install https://github.com/welchbj/bscan/archive/master.tar.gz
```


## Packaging Releases

Install the development requirements:
```sh
pip install -r dev-requirements.txt
```

Build the source and wheel distributions:
```sh
python setup.py bdist_wheel sdist
```

Run post-build checks:
```sh
twine check dist/*
```

Upload to PyPI:
```sh
twine upload dist/*
```