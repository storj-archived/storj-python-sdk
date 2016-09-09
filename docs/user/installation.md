## Installation

This section covers the [Storj][storj] installation.
           

### pip

```
$ pip install storj
```


### source

The code is available at [github][github].

There are several alternatives for this installation method.

Here we only describe two possibilities:

- you can clone the repository:

```
$ git clone git@github.com:Storj/storj-python-sdk.git
```

- you can go to the [releases][releases] tab and
pick a [tarball][tarball] or [zip][zip].

For example:

```
$ curl -OL https://github.com/Storj/storj-python-sdk/archive/1.0.0.tar.gz
```

Once you have a copy of the source and have extracted its files,
you can install it using:

```
$ python setup.py install
```


## command-line

To install the command-line tool do:

```
$ pip install storj[cli]
```


[github]:   https://github.com/Storj/storj-python-sdk/  "Git repo"
[releases]: https://github.com/Storj/storj-python-sdk/releases/ "Releases"
[storj]:    https://storj.io/   "Storj"
[tarball]:  https://github.com/Storj/storj-python-sdk/archive/1.0.0.tar.gz  "Source tarball"
[zip]:  https://github.com/Storj/storj-python-sdk/archive/1.0.0.zip "Source zip"
