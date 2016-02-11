from setuptools import setup, find_packages
import sys, os

version = '0.9.9'


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='b2handle',
      version=version,
      long_description=read('README.md'),
      description=('Library for management of handles '
                   'in the EUDAT project.'),
      classifiers=['Development Status :: 4 - Beta'],
      keywords=['handles', 'PIDs'],
      author='EUDAT project, subtask 5.3.3',
      author_email='buurman@dkrz.de',
      url='http://eudat-b2safe.github.io/B2HANDLE',
      download_url='https://github.com/EUDAT-B2SAFE/B2HANDLE',
      packages=['b2handle','tests'],
      zip_safe=False,
      install_requires=[
          'requests',
          'logging',
          'uuid',
          'datetime',
          'mock',
          'unittest2', # only for py 2.6?
          'unittest',
          'argparse'
      ]
)
