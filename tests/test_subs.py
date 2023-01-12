import enterpriseattack

attack = enterpriseattack.Attack(include_deprecated=True)

subs = []

for technique in attack.techniques:
    if technique.sub_techniques:
        for sub in technique.sub_techniques:
            subs.append(sub.name)
