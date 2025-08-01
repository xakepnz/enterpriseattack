import os
import re
from io import open

from setuptools import find_packages, setup

with open(
    os.path.join(os.path.dirname(__file__), 'enterpriseattack', '__init__.py')
) as fp:
    match = re.search(r"__version__ = ['\"]([^'\"]+)['\"]", fp.read())
    if not match:
        raise RuntimeError('Version string not found')
    VERSION = match.group(1)

with open('README.md', 'r', encoding='utf-8') as fp:
    readme = fp.read()

setup(
    name='enterpriseattack',
    author='xakepnz',
    author_email='xakepnz@pm.me',
    version=VERSION,
    packages=find_packages(exclude=['tests*', 'docs*']),
    description='A lightweight Python module to interact with the '
    'Mitre Att&ck Enterprise framework.',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://gitlab.com/xakepnz/enterpriseattack',
    keywords=[
        'mitre att&ck',
        'att&ck enterprise',
        'enterpriseattack',
        'mitre framework',
        'att&ck',
    ],
    include_package_data=True,
    install_requires=['ujson >= 3.0.0', 'requests >= 2.9.2'],
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
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
