# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#


def test_to_json():
    attack = enterpriseattack.Attack()

    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'campaigns',
        'software', 'tools', 'malware', 'data_sources', 'components',
        'mitigations'
    ]

    for meth in methods:
        assert any(obj.to_json() for obj in getattr(attack, meth))
