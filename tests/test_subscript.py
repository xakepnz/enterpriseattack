# ----------------------------------------------------------------------------#

import enterpriseattack

# ----------------------------------------------------------------------------#

attack = enterpriseattack.Attack(subscriptable=True, update=True)

# ----------------------------------------------------------------------------#

spider = attack.groups.get('Wizard Spider')
print(f'The group: {spider.name} has: {len(spider.aliases)} aliases')

# ----------------------------------------------------------------------------#

evasion = attack.tactics.get('Defense Evasion')
print(f'The tactic: {evasion.name} has: {len(evasion.techniques)} techniques')

# ----------------------------------------------------------------------------#

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
