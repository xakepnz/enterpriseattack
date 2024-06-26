# ----------------------------------------------------------------------------#

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_to_json(attack_update_latest_nonSubscript_deprecated):
    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'campaigns',
        'software', 'tools', 'malware', 'data_sources', 'components',
        'mitigations'
    ]

    for meth in methods:
        assert any(obj.to_json() for obj in getattr(
            attack_update_latest_nonSubscript_deprecated, meth)
        )
