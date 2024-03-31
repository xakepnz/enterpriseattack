# ----------------------------------------------------------------------------#

import ujson  # noqa:F401

import json  # noqa:F401
from timeit import timeit
from pathlib import Path

# ----------------------------------------------------------------------------#

modules = ['json', 'ujson']
NUMBER = 10

_sampleEnterpriseAttack = Path(
    f'{Path(__file__).parent}/enterprise-attack.json'
).absolute()

# ----------------------------------------------------------------------------#

print('Loading/dumping times for the enterprise-attack.json file')
for module in modules:
    print(f'\n[{module}]')

    print(
        'Load time:',
        timeit(
            'obj = json.loads(data)',
            setup=f'import {module} as json; data = '
            f'open("{_sampleEnterpriseAttack}").read()',
            number=NUMBER
        )
    )

    print(
        'Dump time:',
        timeit(
            'json.dumps(obj)',
            setup=f'import {module} as json; obj = '
            f'open("{_sampleEnterpriseAttack}").read()',
            number=NUMBER
        )
    )
