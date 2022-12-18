# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#


def stats():
    print(
        '\nStats:\n\n'
        f'MITRE ATT&CK Version: {attack.mitre_version}\n'
        f'Total Tactics: {len(attack.tactics)}\n'
        f'Total Techniques: {len(attack.techniques)}\n'
        f'Total Sub Techniques: {len(attack.sub_techniques)}\n'
        f'Total Groups: {len(attack.groups)}\n'
        f'Total Software: {len(attack.software)}\n'
        f'Total Datasources: {len(attack.data_sources)}\n'
        f'Total Mitigations: {len(attack.mitigations)}\n'
        f'Total Campaigns: {len(attack.campaigns)}\n'
    )

# ----------------------------------------------------------------------------#


attack = enterpriseattack.Attack(mitre_version='11.3', update=True)
stats()

# ----------------------------------------------------------------------------#

attack = enterpriseattack.Attack(mitre_version='12.1', update=True)
stats()

# ----------------------------------------------------------------------------#

attack = enterpriseattack.Attack(mitre_version='gg', update=True)
stats()
