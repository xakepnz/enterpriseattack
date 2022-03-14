# ----------------------------------------------------------------------------#
# Imports:
# ----------------------------------------------------------------------------#

# Imports:
import logging
import time

# Logger:
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# ----------------------------------------------------------------------------#
# Import tests:
# ----------------------------------------------------------------------------#


def test_i():
    start = time.time()
    import enterpriseattack
    end = time.time()
    print(f'Loading import took: {end - start}')
    return enterpriseattack


enterpriseattack = test_i()

# ----------------------------------------------------------------------------#
# Initialisation tests:
# ----------------------------------------------------------------------------#


def test_pass():
    # start = time.time()
    # attack = enterpriseattack.Attack(
    #     enterprise_json='enterprise-attack.json',
    #     url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    #     include_deprecated=False,
    #     update=True
    # )
    # end = time.time()
    # print(f'Initialise Attack object (fresh download json) took: {end - start}')

    start = time.time()
    attack = enterpriseattack.Attack(
        enterprise_json='tests/enterprise-attack.json',
        url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        include_deprecated=False,
        update=False
    )
    end = time.time()
    print(f'Initialise Attack object (saved json) took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Relationship tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for source, target in attack.relationships.items():
        pass
    end = time.time()
    print(f'Iterate over each relationship object took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Software tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for software in attack.software:
        pass
    end = time.time()
    print(f'Iterate over each software object took: {end - start}')

    start = time.time()
    for software in attack.software:
        software.to_json()
    end = time.time()
    print(f'Iterate over each software object and jsonify it took: {end - start}')

    start = time.time()
    for software in attack.software:
        for group in software.groups:
            pass
    end = time.time()
    print(f'Iterate over each software object and assoc group object took: {end - start}')

    start = time.time()
    for software in attack.software:
        for technique in software.techniques:
            pass
    end = time.time()
    print(f'Iterate over each software object and assoc technique object took: {end - start}')

    start = time.time()
    for software in attack.software:
        for technique in software.techniques:
            for sub_technique in technique.sub_techniques:
                pass
    end = time.time()
    print(f'Iterate over every software/technique/sub_technique object took: {end - start}')

    start = time.time()
    for software in attack.software:
        for group in software.groups:
            pass
    end = time.time()
    print(f'Iterate over each software group object took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Data Source tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for datasource in attack.data_sources:
        pass
    end = time.time()
    print(f'Iterate over each data source object took: {end - start}')

    start = time.time()
    for datasource in attack.data_sources:
        datasource.to_json()
    end = time.time()
    print(f'Iterate over every data source object and jsonify it: {end - start}')

    start = time.time()
    for datasource in attack.data_sources:
        for technique in datasource.techniques:
            print(technique.name)
    end = time.time()
    print(f'Iterate over each data source object and the techniques it took: {end - start}')

    start = time.time()
    for datasource in attack.data_sources:
        for technique in datasource.techniques:
            for sub_technique in technique.sub_techniques:
                pass
    end = time.time()
    print(f'Iterate over each data source/technique/subtechnique objects it took: {end - start}')

    start = time.time()
    for datasource in attack.data_sources:
        for component in datasource.components:
            pass
    end = time.time()
    print(f'Iterate over each data source object and component took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Group tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for group in attack.groups:
        pass
    end = time.time()
    print(f'Iterate over every group object took: {end - start}')

    start = time.time()
    for group in attack.groups:
        group.to_json()
    end = time.time()
    print(f'Jsonify every group object took: {end - start}')

    start = time.time()
    for group in attack.groups:
        for software in group.software:
            pass
    end = time.time()
    print(f'Iterate over every group software object took: {end - start}')

    start = time.time()
    for group in attack.groups:
        for technique in group.techniques:
            pass
    end = time.time()
    print(f'Iterate over every group technique object took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Technique tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for technique in attack.techniques:
        pass
    end = time.time()
    print(f'Iterate over each technique object took: {end - start}')

    start = time.time()
    for technique in attack.techniques:
        for sub_technique in technique.sub_techniques:
            pass
    end = time.time()
    print(f'Iterate over each technique/sub_technique object took: {end - start}')

    start = time.time()
    for technique in attack.techniques:
        for mitigation in technique.mitigations:
            pass
    end = time.time()
    print(f'Iterate over each technique/mitigation object took: {end - start}')

    start = time.time()
    for technique in attack.techniques:
        for tactic in technique.tactics:
            pass
    end = time.time()
    print(f'Iterate over each technique/tactic object took: {end - start}')

    start = time.time()
    for technique in attack.techniques:
        for datasource in technique.datasources:
            pass
    end = time.time()
    print(f'Iterate over each technique/data source object took: {end - start}')

    start = time.time()
    for technique in attack.techniques:
        technique.to_json()
    end = time.time()
    print(f'Iterate over each technique object and jsonify it took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Tactic tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for tactic in attack.tactics:
        pass
    end = time.time()
    print(f'Iterate over each tactic object took: {end - start}')

    start = time.time()
    for tactic in attack.tactics:
        tactic.to_json()
    end = time.time()
    print(f'Iterate over each tactic object and jsonify it took: {end - start}')

    start = time.time()
    for tactic in attack.tactics:
        for technique in tactic.techniques:
            pass
    end = time.time()
    print(f'Iterate over each tactic and technique object took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Sub Technique tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for sub_technique in attack.sub_techniques:
        pass
    end = time.time()
    print(f'Iterate over each sub_technique object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for datasource in sub_technique.datasources:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/data source object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for tactic in sub_technique.tactics:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/tactic object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for technique in sub_technique.techniques:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/tactic object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for mitigation in sub_technique.mitigations:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/tactic object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for group in sub_technique.groups:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/tactic object took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        sub_technique.to_json()
    end = time.time()
    print(f'Iterate over each sub_technique object and jsonify took: {end - start}')

    start = time.time()
    for sub_technique in attack.sub_techniques:
        for mitigation in sub_technique.mitigations:
            pass
    end = time.time()
    print(f'Iterate over each sub_technique/mitigation object took: {end - start}')

    # ----------------------------------------------------------------------------#
    # Mitigation tests:
    # ----------------------------------------------------------------------------#

    start = time.time()
    for mitigation in attack.mitigations:
        pass
    end = time.time()
    print(f'Iterate over each mitigation object took: {end - start}')

    start = time.time()
    for mitigation in attack.mitigations:
        mitigation.to_json()
    end = time.time()
    print(f'Iterate over each mitigation object and jsonify took: {end - start}')

    start = time.time()
    for mitigation in attack.mitigations:
        for technique in mitigation.techniques:
            pass
    end = time.time()
    print(f'Iterate over each mitigation/technique object took: {end - start}')


test_pass()
