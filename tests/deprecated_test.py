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

    assert len(attackNotDeprecated.techniques) \
        != len(attackDeprecated.techniques)

    assert len(attackNotDeprecated.sub_techniques) \
        != len(attackDeprecated.sub_techniques)

    assert len(attackNotDeprecated.groups) \
        != len(attackDeprecated.groups)

    assert len(attackNotDeprecated.software) \
        != len(attackDeprecated.software)

    assert len(attackNotDeprecated.components) \
        != len(attackDeprecated.components)

    assert len(attackNotDeprecated.data_sources) \
        != len(attackDeprecated.data_sources)

    assert len(attackNotDeprecated.mitigations) \
        != len(attackDeprecated.mitigations)
