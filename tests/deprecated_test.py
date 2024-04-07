# ----------------------------------------------------------------------------#

import enterpriseattack
import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_deprecated(attack_update_latest_subscript_deprecated):
    attackNotDeprecated = enterpriseattack.Attack(
        mitre_version='latest',
        subscriptable=True,
        update=True,
        include_deprecated=False
    )

    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'software',
        'tools', 'malware', 'components', 'campaigns', 'mitigations',
        'data_sources'
    ]

    for meth in methods:

        # these methods do not have any deprecated items:
        if meth in ['tactics', 'tools', 'campaigns']:
            assert len(getattr(attackNotDeprecated, meth)) \
                == len(getattr(
                    attack_update_latest_subscript_deprecated, meth)
                    )
        else:
            assert len(getattr(attackNotDeprecated, meth)) \
                != len(getattr(
                    attack_update_latest_subscript_deprecated, meth)
                    )
