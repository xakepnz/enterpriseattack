# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#


def test_deprecated():
    attackNotDeprecated = enterpriseattack.Attack(
        mitre_version='latest',
        subscriptable=True,
        update=True,
        include_deprecated=False
    )

    attackDeprecated = enterpriseattack.Attack(
        mitre_version='latest',
        subscriptable=True,
        update=True,
        include_deprecated=True
    )

    methods = [
        'tactics', 'techniques', 'sub_techniques', 'groups', 'software',
        'tools', 'malware', 'components', 'campaigns', 'mitigations',
        'data_sources'
    ]

    for meth in methods:

        # these methods do not have any deprecated items:
        if meth in ['tactics', 'tools']:
            assert len(getattr(attackNotDeprecated, meth)) \
                == len(getattr(attackDeprecated, meth))
        else:
            assert len(getattr(attackNotDeprecated, meth)) \
                != len(getattr(attackDeprecated, meth))
