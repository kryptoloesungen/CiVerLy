from setuptools import setup, find_packages

setup(
    name='civerly',
    version='1.0.0',
    description='CiVerLy -- The Cipher Verification Library',
    author='cryptosolutions GmbH',
    author_email='contact@cryptosolutions.de',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
)
