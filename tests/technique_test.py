# ----------------------------------------------------------------------------#

# import logging

# ----------------------------------------------------------------------------#

# logging.basicConfig(level=logging.DEBUG)

# ----------------------------------------------------------------------------#


# def test_technique_groups(attack_update_latest_nonSubscript_deprecated):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.groups:
#             _found = True

#             assert len(technique.groups) > 0

#     # if we didn't find any groups, raise assertion error:
#     if _found is False:
#         raise AssertionError('No groups found')

# ----------------------------------------------------------------------------#


# def test_technique_tools(attack_update_latest_nonSubscript_deprecated):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.tools:
#             _found = True

#             assert len(technique.tools) > 0

#     # if we didn't find any tools, raise assertion error:
#     if _found is False:
#         raise AssertionError('No tools found')

# ----------------------------------------------------------------------------#


# def test_technique_components(
#         attack_update_latest_nonSubscript_deprecated
#         ):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.components:
#             _found = True

#             assert len(technique.components) > 0

#     # if we didn't find any components, raise assertion error:
#     if _found is False:
#         raise AssertionError('No components found')

# ----------------------------------------------------------------------------#


# def test_technique_datasources(
#         attack_update_latest_nonSubscript_deprecated
#         ):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.datasources:
#             _found = True

#             assert len(technique.datasources) > 0

#     # if we didn't find any datasources, raise assertion error:
#     if _found is False:
#         raise AssertionError('No datasources found')

# ----------------------------------------------------------------------------#


# def test_technique_mitigations(
#         attack_update_latest_nonSubscript_deprecated
#         ):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.mitigations:
#             _found = True

#             assert len(technique.mitigations) > 0

#     # if we didn't find any mitigations, raise assertion error:
#     if _found is False:
#         raise AssertionError('No mitigations found')

# ----------------------------------------------------------------------------#


# def test_technique_software(
#         attack_update_latest_nonSubscript_deprecated
#         ):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.software:
#             _found = True

#             assert len(technique.software) > 0

#     # if we didn't find any software, raise assertion error:
#     if _found is False:
#         raise AssertionError('No software found')

# ----------------------------------------------------------------------------#


# def test_technique_malware(
#         attack_update_latest_nonSubscript_deprecated
#         ):
#     _found = False

#     for technique in \
#             attack_update_latest_nonSubscript_deprecated.techniques:
#         if technique.malware:
#             _found = True

#             assert len(technique.malware) > 0

#     # if we didn't find any malware, raise assertion error:
#     if _found is False:
#         raise AssertionError('No malware found')
