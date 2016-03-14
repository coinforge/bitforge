import setuptools
import sys

setuptools.setup(
  name = 'bitforge',
  version = '0.3',
  url = 'https://github.com/coinforge/bitforge',

  author = 'Yemel Jardi',
  author_email = 'angel.jardi@gmail.com',

  description = 'A python bitcoin library',
  keywords = ['bitcoin', 'altcoin'], # arbitrary keywords

  packages = setuptools.find_packages(),

  setup_requires=['pytest-runner'],
  tests_require=['pytest', 'pytest-cov'],
  install_requires = ['ecdsa==0.13'] + (['enum34==1.0.4'] if sys.version_info < (3, 4) else []),

  classifiers = [],
)
