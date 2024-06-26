# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_str_repr(attack_local):
    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'campaigns',
        'software', 'tools', 'malware', 'data_sources', 'components',
        'mitigations'
    ]

    for meth in methods:

        for obj in getattr(attack_local, meth):
            assert str(obj)

        for obj in getattr(attack_local, meth):
            assert repr(obj)
