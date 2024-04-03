# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#


def test_to_json():
    attack = enterpriseattack.Attack()

    for tact in attack.tactics:
        assert tact.to_json()

    for tech in attack.techniques:
        assert tech.to_json()

    for sub in attack.sub_techniques:
        assert sub.to_json()

    for group in attack.groups:
        assert group.to_json()

    for campaign in attack.campaigns:
        assert campaign.to_json()

    for software in attack.software:
        assert software.to_json()

    for ds in attack.data_sources:
        assert ds.to_json()

    for comp in attack.components:
        assert comp.to_json()

    for mitigation in attack.mitigations:
        assert mitigation.to_json()
