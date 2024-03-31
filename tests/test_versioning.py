# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#

versions = [
    '11.1', '11.2', '11.3', '12.0', '12.1', '13.0', '13.1', '14.0', '14.1'
]

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


for version in versions:
    attack = enterpriseattack.Attack(mitre_version=version, update=True)
    stats()
