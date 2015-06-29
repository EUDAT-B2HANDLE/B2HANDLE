from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='b2handle',
      version=version,
      description="b2handle interface library",
      long_description="""\
this interface will replace the current epic api""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='eudat subtask 5.3.3',
      author_email='weigel@dkrz.de',
      url='dkrz.de',
      license='',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'nose'
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
