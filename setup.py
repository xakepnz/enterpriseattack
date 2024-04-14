# ----------------------------------------------------------------------------#

import os
import re
from setuptools import setup, find_packages
from io import open

# ----------------------------------------------------------------------------#

with open(
    os.path.join(
        os.path.dirname(__file__),
        'enterpriseattack',
        '__init__.py'
        )) as fp:
    VERSION = re.match(r'.*__version__ = \'(.*?)\'', fp.read(), re.S).group(1)

# ----------------------------------------------------------------------------#

with open('README.md', 'r', encoding='utf-8') as fp:
    README = fp.read()

# ----------------------------------------------------------------------------#

with open('requirements.txt', 'r', encoding='utf-8') as fp:
    REQUIREMENTS = fp.read().splitlines()

# ----------------------------------------------------------------------------#

setup(
    name='enterpriseattack',
    author='xakepnz',
    author_email='xakepnz@pm.me',
    version=VERSION,
    packages=find_packages(exclude=['tests*', 'docs*']),
    description='A lightweight Python module to interact with the '
                '[MITRE ATT&CK®](https://attack.mitre.org/) Enterprise '
                'dataset. Built for speed with minimal dependencies. '
                '[Read the docs](https://gitlab.com/xakepnz/enterpriseattack/tree/main/docs) '  # noqa: E501
                'for more info.',
    long_description=README,
    long_description_content_type='text/markdown',
    url='https://gitlab.com/xakepnz/enterpriseattack',
    keywords=[
        'mitre att&ck',
        'att&ck enterprise',
        'enterpriseattack',
        'mitre framework',
        'att&ck',
        'python MITRE ATT&CK'
    ],
    include_package_data=True,
    install_requires=REQUIREMENTS,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
