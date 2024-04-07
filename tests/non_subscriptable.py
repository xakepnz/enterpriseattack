# ----------------------------------------------------------------------------#

import enterpriseattack

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_non_subscriptable():

    for deprecatedBool in [True, False]:

        attack = enterpriseattack.Attack(
            mitre_version='latest',
            subscriptable=False,
            update=True,
            include_deprecated=deprecatedBool
        )

        assert 'Lazarus Group' in [obj.name for obj in attack.groups]
        assert 'Resource Development' in [obj.name for obj in attack.tactics]
        assert 'Process Injection' in [obj.name for obj in attack.techniques]
        assert 'SSH Hijacking' in [obj.name for obj in attack.sub_techniques]
        assert 'Network Traffic' in [obj.name for obj in attack.data_sources]
        assert 'Code Signing' in [obj.name for obj in attack.mitigations]
        assert 'Cobalt Strike' in [obj.name for obj in attack.software]
        assert 'Operation Sharpshooter' in [
            obj.name for obj in attack.campaigns
        ]
