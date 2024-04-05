# ----------------------------------------------------------------------------#

import enterpriseattack

from pathlib import Path

# ----------------------------------------------------------------------------#


def test_str_repr():
    localJson = f'{Path(__file__).parent}/data/enterprise-attack.json'

    attack = enterpriseattack.Attack(enterprise_json=localJson)

    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'campaigns',
        'software', 'tools', 'malware', 'data_sources', 'components',
        'mitigations'
    ]

    for meth in methods:
        assert str(any(obj) for obj in getattr(attack, meth))
        assert repr(any(obj) for obj in getattr(attack, meth))
