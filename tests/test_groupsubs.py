# --------------------------------------------------------------------------- #

import enterpriseattack
print(f'{enterpriseattack.__version__=}')

# --------------------------------------------------------------------------- #

attack = enterpriseattack.Attack(
    include_deprecated=False,
    update=True
)

# --------------------------------------------------------------------------- #

for group in attack.groups:
    print(
        f'{group.id}: '
        f'{", ".join(t.id for t in group.techniques + group.sub_techniques)}'
    )
