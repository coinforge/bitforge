import setuptools

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
  tests_require=['pytest'],
  install_requires = ['enum34==1.0.4', 'ecdsa==0.13', 'pytest==2.7.0', 'nose==1.3.6'],

  classifiers = [],
)
