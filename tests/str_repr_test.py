# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#


def test_str_repr():
    attack = enterpriseattack.Attack()

    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'campaigns',
        'software', 'tools', 'malware', 'data_sources', 'components',
        'mitigations'
    ]

    for meth in methods:
        assert str(any(obj) for obj in getattr(attack, meth))
        assert repr(any(obj) for obj in getattr(attack, meth))
