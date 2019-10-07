import codecs
import os
import re
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class NoseTestCommand(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)

        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import nose

        test_script = os.path.join('b2handle', 'tests', 'main_test_script.py')
        # See also nosetests section in setup.cfg
        nose.run_exit(argv=['nosetests', test_script])


# Set common test dependencies
test_dependencies = [
    'mock',
    'nose',
]

if sys.version_info < (2, 7):
    test_dependencies.append('argparse')
    test_dependencies.append('unittest2')
    # Workaround for atexit._run_exitfuncs error when invoking `test` with
    # older versions of Python
    try:
        import multiprocessing
    except ImportError:
        pass


here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    # Intentionally *not* adding an encoding option to open, See:
    #   https://github.com/pypa/virtualenv/issues/201#issuecomment-3145690
    return codecs.open(os.path.join(here, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


# Note: The package maintainer needs pypandoc and pygments to properly convert
# the Markdown-formatted README into RestructuredText before uploading to PyPi
# See https://bitbucket.org/pypa/pypi/issues/148/support-markdown-for-readmes
try:
    import pypandoc
    long_description=pypandoc.convert('README.md', 'rst')
except(IOError, ImportError):
    long_description=open('README.md').read()

setup(name='b2handle',
      version=find_version("b2handle", "__init__.py"),
      description=('Library for management of handles '
                   'in the EUDAT project.'),
      long_description=long_description,
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'License :: OSI Approved :: Apache Software License',
          'Intended Audience :: Developers',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      keywords=['handles', 'PIDs'],
      author='EUDAT project, subtask 5.3.3',
      author_email='buurman@dkrz.de',
      url='http://eudat-b2safe.github.io/B2HANDLE',
      download_url='https://github.com/EUDAT-B2SAFE/B2HANDLE',
      license='Apache License 2.0',
      packages=['b2handle', 'b2handle/util', 'b2handle/tests', 'b2handle/tests/testcases'],
      zip_safe=False,
      install_requires=[
          'requests',
          'datetime',
          'future',
          'six',
      ],
      tests_require=test_dependencies,
      python_requires='>=2.6,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,<3.8',
      cmdclass={'test': NoseTestCommand},
      include_package_data=True
)
