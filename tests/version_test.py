# ----------------------------------------------------------------------------#

import enterpriseattack

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)

versions = [
    '11.1', '11.2', '11.3', '12.0', '12.1', '13.0', '13.1', '14.0', '14.1',
    'latest'
]

# ----------------------------------------------------------------------------#


def test_versions():

    for version in versions:

        attack = enterpriseattack.Attack(mitre_version=version, update=True)

        assert attack.mitre_version
