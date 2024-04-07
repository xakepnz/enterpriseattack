# ----------------------------------------------------------------------------#

import enterpriseattack

import logging

# ----------------------------------------------------------------------------#

logging.basicConfig(level=logging.DEBUG)


def test_subscriptable():

    for deprecatedBool in [True, False]:

        attack = enterpriseattack.Attack(
            mitre_version='latest',
            subscriptable=True,
            update=True,
            include_deprecated=deprecatedBool
        )

        assert attack.groups.get('Wizard Spider') is not None
        assert attack.tactics.get('Defense Evasion') is not None
        assert attack.techniques.get('Phishing') is not None
        assert attack.sub_techniques.get('Malicious File') is not None
        assert attack.data_sources.get('Kernel') is not None
        assert attack.mitigations.get('Code Signing') is not None
        assert attack.software.get('Duqu') is not None
        assert attack.campaigns.get('Operation Dust Storm') is not None
