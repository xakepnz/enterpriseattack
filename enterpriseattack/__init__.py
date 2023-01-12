# ----------------------------------------------------------------------------#

from os import path

from enterpriseattack import campaign
from enterpriseattack import component
from enterpriseattack import data_source
from enterpriseattack import group
from enterpriseattack import mitigation
from enterpriseattack import software
from enterpriseattack import sub_technique
from enterpriseattack import tactic
from enterpriseattack import technique
from enterpriseattack import utils

# ----------------------------------------------------------------------------#

__version__ = '0.1.8'

# ----------------------------------------------------------------------------#
# enterpriseattack Attack class:
# ----------------------------------------------------------------------------#


class Attack:
    def __init__(
            self,
            enterprise_json=None,
            url='https://raw.githubusercontent.com/mitre/cti/master/'
                'enterprise-attack/enterprise-attack.json',
            include_deprecated=False,
            update=False,
            mitre_version='latest',
            subscriptable=False,
            **kwargs):

        # Set subscriptable bool, this allows for .get(str) against properies:
        self.subscriptable = subscriptable

        # Change url to specific Mitre ATT&CK version if user supplied
        # Remove 'v' if user supplied in version:
        self.mitre_version = mitre_version
        if mitre_version != 'latest':
            url = (
                'https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v'
                f'{mitre_version.replace("v", "")}/enterprise-attack/'
                'enterprise-attack.json'
            )

        # Save the json dump to the same directory the script lives if
        # none supplied:
        if not enterprise_json:
            enterprise_json = (
                f'{path.dirname(path.realpath(__file__))}'
                '/enterprise-attack.json'
            )
            self.enterprise_json = enterprise_json

        # Parse the json:
        self.attack_objects = utils.read_json(
            url,
            enterprise_json,
            update,
            **kwargs
        )

        # Allow for including depreciated items Mitre has revoked:
        self.include_deprecated = include_deprecated

        # Set the relationships of all objects, and create a dict
        # sorted by ID's:
        self.relationships, self.id_lookup = utils.set_relationships(
            self.attack_objects
        )

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack tactics:
    # ----------------------------------------------------------------------------#

    @property
    def tactics(self):
        if self.subscriptable:
            tactics_ = {}
        else:
            tactics_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'x-mitre-tactic':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            tactics_.append(
                                tactic.Tactic(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            tactics_[
                                attack_obj.get('name')
                            ] = tactic.Tactic(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        tactics_.append(
                            tactic.Tactic(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        tactics_[
                            attack_obj.get('name')
                        ] = tactic.Tactic(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return tactics_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack techniques:
    # ----------------------------------------------------------------------------#

    @property
    def techniques(self):
        if self.subscriptable:
            techniques_ = {}
        else:
            techniques_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'attack-pattern':
                if not attack_obj.get('x_mitre_is_subtechnique'):
                    if not self.include_deprecated:
                        if not attack_obj.get('x_mitre_deprecated'):
                            if not self.subscriptable:
                                techniques_.append(
                                    technique.Technique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj
                                    )
                                )
                            else:
                                techniques_[
                                    attack_obj.get('name')
                                ] = technique.Technique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )

                    else:
                        if not self.subscriptable:
                            techniques_.append(
                                technique.Technique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            techniques_[
                                attack_obj.get('name')
                            ] = technique.Technique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )

        return techniques_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack sub_techniques:
    # ----------------------------------------------------------------------------#

    @property
    def sub_techniques(self):
        if self.subscriptable:
            sub_techniques_ = {}
        else:
            sub_techniques_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'attack-pattern':
                if attack_obj.get('x_mitre_is_subtechnique'):
                    if not self.include_deprecated:
                        if not attack_obj.get('x_mitre_deprecated'):
                            if not self.subscriptable:
                                sub_techniques_.append(
                                    sub_technique.SubTechnique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj
                                    )
                                )
                            else:
                                sub_techniques_[
                                    attack_obj.get('name')
                                ] = sub_technique.SubTechnique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                    else:
                        if not self.subscriptable:
                            sub_techniques_.append(
                                sub_technique.SubTechnique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            sub_techniques_[
                                attack_obj.get('name')
                            ] = sub_technique.SubTechnique(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )

        return sub_techniques_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack groups:
    # ----------------------------------------------------------------------------#

    @property
    def groups(self):
        if self.subscriptable:
            groups_ = {}
        else:
            groups_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'intrusion-set':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            groups_.append(
                                group.Group(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            groups_[
                                attack_obj.get('name')
                            ] = group.Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        groups_.append(
                            group.Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        groups_[
                            attack_obj.get('name')
                        ] = group.Group(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return groups_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack software:
    # ----------------------------------------------------------------------------#

    @property
    def software(self):
        if self.subscriptable:
            software_ = {}
        else:
            software_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') in ['tool', 'malware']:
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            software_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            software_[
                                attack_obj.get('name')
                            ] = software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        software_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        software_[
                            attack_obj.get('name')
                        ] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return software_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack malware:
    # ----------------------------------------------------------------------------#

    @property
    def malware(self):
        if self.subscriptable:
            malware_ = {}
        else:
            malware_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'malware':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            malware_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            malware_[
                                attack_obj.get('name')
                            ] = software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        malware_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        malware_[
                            attack_obj.get('name')
                        ] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return malware_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack tools:
    # ----------------------------------------------------------------------------#

    @property
    def tools(self):
        if self.subscriptable:
            tools_ = {}
        else:
            tools_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'tool':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            tools_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            tools_[
                                attack_obj.get('name')
                            ] = software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        tools_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        tools_[
                            attack_obj.get('name')
                        ] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return tools_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack mitigations:
    # ----------------------------------------------------------------------------#

    @property
    def mitigations(self):
        if self.subscriptable:
            mitigations_ = {}
        else:
            mitigations_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'course-of-action':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            mitigations_.append(
                                mitigation.Mitigation(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            mitigations_[
                                attack_obj.get('name')
                            ] = mitigation.Mitigation(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        mitigations_.append(
                            mitigation.Mitigation(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        mitigations_[
                            attack_obj.get('name')
                        ] = mitigation.Mitigation(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return mitigations_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack data_sources:
    # ----------------------------------------------------------------------------#

    @property
    def data_sources(self):
        if self.subscriptable:
            data_sources_ = {}
        else:
            data_sources_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'x-mitre-data-source':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            data_sources_.append(
                                data_source.DataSource(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            data_sources_[
                                attack_obj.get('name')
                            ] = data_source.DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        data_sources_.append(
                            data_source.DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        data_sources_[
                            attack_obj.get('name')
                        ] = data_source.DataSource(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return data_sources_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack components:
    # ----------------------------------------------------------------------------#

    @property
    def components(self):
        if self.subscriptable:
            components_ = {}
        else:
            components_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'x-mitre-data-component':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            components_.append(
                                component.Component(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            components_[
                                attack_obj.get('name')
                            ] = component.Component(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        components_.append(
                            component.Component(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        components_[
                            attack_obj.get('name')
                        ] = component.Component(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return components_

    # ----------------------------------------------------------------------------#
    # Return all enterpriseattack campaigns:
    # ----------------------------------------------------------------------------#

    @property
    def campaigns(self):
        if self.subscriptable:
            campaigns_ = {}
        else:
            campaigns_ = []

        for attack_obj in self.attack_objects.get('objects'):
            if attack_obj.get('type') == 'campaign':
                if not self.include_deprecated:
                    if not attack_obj.get('x_mitre_deprecated'):
                        if not self.subscriptable:
                            campaigns_.append(
                                campaign.Campaign(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj
                                )
                            )
                        else:
                            campaigns_[
                                attack_obj.get('name')
                            ] = campaign.Campaign(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                else:
                    if not self.subscriptable:
                        campaigns_.append(
                            campaign.Campaign(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj
                            )
                        )
                    else:
                        campaigns_[
                            attack_obj.get('name')
                        ] = campaign.Campaign(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj
                        )

        return campaigns_

# ----------------------------------------------------------------------------#
# Exception class for errors:
# ----------------------------------------------------------------------------#


class Error(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message
