# ![bscan](static/logo.png)

[![Travis Status](https://img.shields.io/travis/welchbj/bscan/master.svg?style=flat-square&label=travis)](https://travis-ci.org/welchbj/bscan) [![PyPI](https://img.shields.io/pypi/v/bscan.svg?style=flat-square&label=pypi)](https://pypi.org/project/bscan/) [![Python Versions](https://img.shields.io/badge/python-3.6-c944ff.svg?style=flat-square)](https://pypi.org/project/bscan/)

An asynchronous network scanning, enumeration, and recommendation tool.


## Installation

``` sh
pip install bscan
```


## Packaging Releases

Install the development requirements
``` sh
pip install -r dev-requirements.txt
```

Build the source and wheel distributions
``` sh
python setup.py bdist_wheel sdist
```

Run post-build checks
``` sh
twine check dist/*
```

Upload to PyPI
``` sh
twine upload dist/*
```