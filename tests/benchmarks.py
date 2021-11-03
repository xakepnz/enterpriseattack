#---------------------------------------------------------------------------------#
# Imports:
#---------------------------------------------------------------------------------#

# Imports:
import logging
import time

# Logger:
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#---------------------------------------------------------------------------------#
# Import tests:
#---------------------------------------------------------------------------------#

start = time.time()
import enterpriseattack
end = time.time()
print('Loading import took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Initialisation tests:
#---------------------------------------------------------------------------------#

t1 = time.time()
attack = enterpriseattack.Attack(
    enterprise_json='enterpriseattack/data/enterprise-attack.json',
    url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    include_deprecated=False,
    update=True
)
t11 = time.time()
print('Initialise Attack object (fresh download json) took: {}'.format(t11 - t1))

start = time.time()
attack = enterpriseattack.Attack(
    enterprise_json='enterpriseattack/data/enterprise-attack.json',
    url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    include_deprecated=False,
    update=False
)
end = time.time()
print('Initialise Attack object (saved json) took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Relationship tests:
#---------------------------------------------------------------------------------#

start = time.time()
for source, target in attack.relationships.items():
    pass
end = time.time()
print('Iterate over each relationship object took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Software tests:
#---------------------------------------------------------------------------------#

start = time.time()
for software in attack.software:
    pass
end = time.time()
print('Iterate over each software object took: {}'.format(end - start))

start = time.time()
for software in attack.software:
    software.to_json()
end = time.time()
print('Iterate over each software object and jsonify it took: {}'.format(end - start))

start = time.time()
for software in attack.software:
    for group in software.groups:
        pass
end = time.time()
print('Iterate over each software object and assoc group object took: {}'.format(end - start))

start = time.time()
for software in attack.software:
    for technique in software.techniques:
        pass
end = time.time()
print('Iterate over each software object and assoc technique object took: {}'.format(end - start))

start = time.time()
for software in attack.software:
    for technique in software.techniques:
        for sub_technique in technique.sub_techniques:
            pass
end = time.time()
print('Iterate over every software/technique/sub_technique object took: {}'.format(end - start))

start = time.time()
for software in attack.software:
    for group in software.groups:
        pass
end = time.time()
print('Iterate over each software group object took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Data Source tests:
#---------------------------------------------------------------------------------#

start = time.time()
for datasource in attack.data_sources:
    pass
end = time.time()
print('Iterate over each data source object took: {}'.format(end - start))

start = time.time()
for datasource in attack.data_sources:
    datasource.to_json()
end = time.time()
print('Iterate over every data source object and jsonify it: {}'.format(end - start))

start = time.time()
for datasource in attack.data_sources:
    for technique in datasource.techniques:
        print(technique.name)
end = time.time()
print('Iterate over each data source object and the techniques it took: {}'.format(end - start))

start = time.time()
for datasource in attack.data_sources:
    for technique in datasource.techniques:
        for sub_technique in technique.sub_techniques:
            pass
end = time.time()
print('Iterate over each data source/technique/subtechnique objects it took: {}'.format(end - start))

start = time.time()
for datasource in attack.data_sources:
    for component in datasource.components:
        pass
end = time.time()
print('Iterate over each data source object and component took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Group tests:
#---------------------------------------------------------------------------------#

start = time.time()
for group in attack.groups:
    pass
end = time.time()
print('Iterate over every group object took: {}'.format(end - start))

start = time.time()
for group in attack.groups:
    group.to_json()
end = time.time()
print('Jsonify every group object took: {}'.format(end - start))

start = time.time()
for group in attack.groups:
    for software in group.software:
        print(software.name)
end = time.time()
print('Iterate over every group software object took: {}'.format(end - start))

start = time.time()
for group in attack.groups:
    for technique in group.techniques:
        pass
end = time.time()
print('Iterate over every group technique object took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Technique tests:
#---------------------------------------------------------------------------------#

start = time.time()
for technique in attack.techniques:
    pass
end = time.time()
print('Iterate over each technique object took: {}'.format(end - start))

start = time.time()
for technique in attack.techniques:
    for sub_technique in technique.sub_techniques:
        pass
end = time.time()
print('Iterate over each technique/sub_technique object took: {}'.format(end - start))

start = time.time()
for technique in attack.techniques:
    for mitigation in technique.mitigations:
        pass
end = time.time()
print('Iterate over each technique/mitigation object took: {}'.format(end - start))

start = time.time()
for technique in attack.techniques:
    for tactic in technique.tactics:
        pass
end = time.time()
print('Iterate over each technique/tactic object took: {}'.format(end - start))

start = time.time()
for technique in attack.techniques:
    for datasource in technique.datasources:
        pass
end = time.time()
print('Iterate over each technique/data source object took: {}'.format(end - start))

start = time.time()
for technique in attack.techniques:
    technique.to_json()
end = time.time()
print('Iterate over each technique object and jsonify it took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Tactic tests:
#---------------------------------------------------------------------------------#

start = time.time()
for tactic in attack.tactics:
    pass
end = time.time()
print('Iterate over each tactic object took: {}'.format(end - start))

start = time.time()
for tactic in attack.tactics:
    tactic.to_json()
end = time.time()
print('Iterate over each tactic object and jsonify it took: {}'.format(end - start))

start = time.time()
for tactic in attack.tactics:
    for technique in tactic.techniques:
        pass
end = time.time()
print('Iterate over each tactic and technique object took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Sub Technique tests:
#---------------------------------------------------------------------------------#

start = time.time()
for sub_technique in attack.sub_techniques:
    pass
end = time.time()
print('Iterate over each sub_technique object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for datasource in sub_technique.datasources:
        pass
end = time.time()
print('Iterate over each sub_technique/data source object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for tactic in sub_technique.tactics:
        pass
end = time.time()
print('Iterate over each sub_technique/tactic object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for technique in sub_technique.techniques:
        print(technique.name)
end = time.time()
print('Iterate over each sub_technique/tactic object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for mitigation in sub_technique.mitigations:
        print(mitigation.name)
end = time.time()
print('Iterate over each sub_technique/tactic object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for group in sub_technique.groups:
        print(sub_technique.name, group.name)
end = time.time()
print('Iterate over each sub_technique/tactic object took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    sub_technique.to_json()
end = time.time()
print('Iterate over each sub_technique object and jsonify took: {}'.format(end - start))

start = time.time()
for sub_technique in attack.sub_techniques:
    for mitigation in sub_technique.mitigations:
        pass
end = time.time()
print('Iterate over each sub_technique/mitigation object took: {}'.format(end - start))

#---------------------------------------------------------------------------------#
# Mitigation tests:
#---------------------------------------------------------------------------------#

start = time.time()
for mitigation in attack.mitigations:
    pass
end = time.time()
print('Iterate over each mitigation object took: {}'.format(end - start))

start = time.time()
for mitigation in attack.mitigations:
    mitigation.to_json()
end = time.time()
print('Iterate over each mitigation object and jsonify took: {}'.format(end - start))

start = time.time()
for mitigation in attack.mitigations:
    for technique in mitigation.techniques:
        pass
end = time.time()
print('Iterate over each mitigation/technique object took: {}'.format(end - start))
