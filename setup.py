import os
import codecs
import versioneer
from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with codecs.open(os.path.join(HERE, *parts), 'rb', 'utf-8') as f:
        return f.read()


setup(
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    name='txacme',
    description='ACME protocol implementation for Twisted',
    license='Expat',
    url='https://github.com/mithrandi/txacme',
    author='Tristan Seligmann',
    author_email='mithrandi@mithrandi.net',
    maintainer='Tristan Seligmann',
    maintainer_email='mithrandi@mithrandi.net',
    long_description=read('README.rst'),
    packages=find_packages(where='src') + ['twisted.plugins'],
    package_dir={'': 'src'},
    zip_safe=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    install_requires=[
        'acme>=0.21.0',
        'attrs>=17.4.0',
        'eliot>=0.8.0',
        'josepy',
        'pem>=16.1.0',
        'treq>=15.1.0',
        'twisted[tls]>=15.5.0',
        'txsni',
        'pyopenssl>=17.1.0',
        ],
    extras_require={
        'libcloud': [
            'apache-libcloud',
        ],
        'test': [
            'fixtures>=1.4.0',
            'hypothesis>=3.20.0,<4.0.0',
            'service_identity>=17.0.0',
            'testrepository>=0.0.20',
            'testscenarios',
            'testtools>=2.1.0',
            ],
        },
    )
