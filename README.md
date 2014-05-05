# _pymisc_

_pymisc is a set of small, reusable code snippets which I could not find in
other python modules._

## Project Setup

In order to use pymisc following dependencies have to be installed:
- yaml bindings for python (http://pyyaml.org/)
- python 2.7 or python >=3.2

In order to send event to Riemann, few more libraries are needed:
- Bernhard - Riemann client library (https://github.com/banjiewen/bernhard)
- Google's protobuf library
- dnspython library (http://www.dnspython.org/)

You can also use debian packaging rules from debian/ directory to build a deb
package.

## Usage

All functions are documented using pydoc syntax. By convention all private
methods/fields are prefixed with "\_" and should not be accessed directly.

## Contributing

All patches are welcome ! Please use Github issue tracking and/or create a pull
request.

Also, please try to adhere to Google coding standards:

http://google-styleguide.googlecode.com/svn/trunk/pyguide.html#Default_Argument_Values

### Testing

Currenlty the unittest python library is used to perform all the testing. In
test/ directory you can find:
- modules/ - modules used by unittests
- moduletests/ - the unittests themselves
- fabric/ - sample input files and test certificates temporary directories
- output_coverage_html/ - coverage tests results in a form of an html webpage

Unittests can be started either by using *nosetest* command:

```
pymisc/ (master✗) # nosetests
[20:33:02]
......
----------------------------------------------------------------------
Ran 6 tests in 0.449s

OK
```

or by issuing the *run_tests.py* command:

```
pymisc/ (master✗) # run_tests.py
[20:33:04]
......
----------------------------------------------------------------------
Ran 6 tests in 0.362s

OK
```

The difference is that the *run_tests.py* takes care of generating coverage
reports for you.

All the dependencies required for performing the unittests are decribed in debian
packaging scripts and are as follows:
- unittests2 (in case of python2)
- coverage
- python-mock
, plus all the dependencies mentioned in 'Project Setup' section.
