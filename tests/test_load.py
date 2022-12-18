# ----------------------------------------------------------------------------#

import ujson  # noqa:F401

import json  # noqa:F401
from timeit import timeit

# ----------------------------------------------------------------------------#

modules = ['json', 'ujson']
NUMBER = 10

# ----------------------------------------------------------------------------#

for module in modules:
    print(f'\n[{module}]')

    print(
        'Load time:',
        timeit(
            'obj = json.loads(data)',
            setup=f'import {module} as json; data = open('
                  '"enterprise-attack.json").read()',
            number=NUMBER
        )
    )

    print(
        'Dump time:',
        timeit(
            'json.dumps(obj)',
            setup=f'import {module} as json; obj = json.dumps(open('
                  '"enterprise-attack.json").read())',
            number=NUMBER
        )
    )
