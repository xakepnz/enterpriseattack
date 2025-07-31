# -----------------------------------------------------------------------------

from __future__ import annotations

from os import path
from typing import Any, Dict, List, Optional, Union

from enterpriseattack import (
    campaign,
    component,
    data_source,
    group,
    mitigation,
    software,
    sub_technique,
    tactic,
    technique,
    utils,
)

# -----------------------------------------------------------------------------

__version__ = "1.0.3"

# -----------------------------------------------------------------------------
# enterpriseattack Attack class:
# -----------------------------------------------------------------------------


class Attack:

    # -------------------------------------------------------------------------

    def __init__(
        self,
        enterprise_json: Optional[Union[str, Dict[str, Any]]] = None,
        url: str = "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json",
        include_deprecated: bool = False,
        update: bool = False,
        mitre_version: str = "latest",
        subscriptable: bool = False,
        **kwargs: Any,
    ) -> Attack:
        """
        Initialize the Attack object with MITRE ATT&CK Enterprise data.

        The Attack class provides access to MITRE ATT&CK Enterprise
        framework data, including techniques, tactics, groups, software,
        mitigations, and more. Data can be loaded from a local JSON file,
        a custom URL, or the default MITRE repository.

        Args:
            enterprise_json: Local path to enterprise-attack.json file or
                pre-loaded JSON data as a dictionary. If None, data will be
                downloaded from the specified URL.
            url: URL to download the enterprise-attack.json file from.
                Defaults to the official MITRE ATT&CK repository.
            include_deprecated: Whether to include deprecated ATT&CK objects
                in the loaded data. Defaults to False.
            update: Force update/re-download of data even if local cache
                exists. Defaults to False.
            mitre_version: Specific version of MITRE ATT&CK data to use.
                Defaults to 'latest'.
            subscriptable: Enable subscriptable access to ATT&CK objects
                (e.g., attack['T1055']). Defaults to False.
            **kwargs: Additional keyword arguments for customization.

        Raises:
            FileNotFoundError: If enterprise_json path is provided but file
                doesn't exist.
            requests.RequestException: If URL download fails.
            json.JSONDecodeError: If JSON data is malformed.
            ValueError: If provided data doesn't contain valid ATT&CK
                structure.

        Example:
            >>> # Load from default MITRE repository
            >>> attack = Attack()

            >>> # Load from local file
            >>> attack = Attack(
            ...     enterprise_json='./data/enterprise-attack.json'
            ... )

            >>> # Include deprecated objects
            >>> attack = Attack(include_deprecated=True)

            >>> # Enable subscriptable access
            >>> attack = Attack(subscriptable=True)
            >>> technique = attack['T1055']  # Process Injection
        """
        # Set subscriptable bool, this allows for .get(str) against properies:
        self.subscriptable = subscriptable

        # Change url to specific Mitre ATT&CK version if user supplied
        # Remove 'v' if user supplied in version:
        self.mitre_version = mitre_version
        if mitre_version != "latest":
            url = (
                "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v"
                f'{mitre_version.replace("v", "")}/enterprise-attack/'
                "enterprise-attack.json"
            )

        # Save the json dump to the same directory the script lives if
        # none supplied:
        if not enterprise_json:
            enterprise_json = (
                f"{path.dirname(path.realpath(__file__))}"
                "/enterprise-attack.json"
            )
            self.enterprise_json = enterprise_json

        # Parse the json:
        self.attack_objects = utils.read_json(
            url, enterprise_json, update, **kwargs
        )

        # Allow for including depreciated items Mitre has revoked:
        self.include_deprecated = include_deprecated

        # Set the relationships of all objects, and create a dict
        # sorted by ID's:
        self.relationships, self.id_lookup = utils.set_relationships(
            self.attack_objects
        )

    # -------------------------------------------------------------------------

    @property
    def tactics(self) -> Union[List[tactic.Tactic], Dict[str, tactic.Tactic]]:
        """Get all tactics from the ATT&CK framework.

        Returns:
            List of Tactic objects if subscriptable=False, otherwise a
            dictionary mapping tactic names to Tactic objects.
        """
        if self.subscriptable:
            tactics_ = {}
        else:
            tactics_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "x-mitre-tactic":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            tactics_.append(
                                tactic.Tactic(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            tactics_[attack_obj.get("name")] = tactic.Tactic(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                else:
                    if not self.subscriptable:
                        tactics_.append(
                            tactic.Tactic(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        tactics_[attack_obj.get("name")] = tactic.Tactic(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return tactics_

    # -------------------------------------------------------------------------

    @property
    def techniques(
        self,
    ) -> Union[List[technique.Technique], Dict[str, technique.Technique]]:
        """
        Get all techniques from the ATT&CK framework.

        Returns:
            List of Technique objects if subscriptable=False, otherwise a
            dictionary mapping technique names to Technique objects.
            Excludes sub-techniques.
        """
        if self.subscriptable:
            techniques_ = {}
        else:
            techniques_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "attack-pattern":
                if not attack_obj.get("x_mitre_is_subtechnique"):
                    if not self.include_deprecated:
                        if not attack_obj.get("x_mitre_deprecated"):
                            if not self.subscriptable:
                                techniques_.append(
                                    technique.Technique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj,
                                    )
                                )
                            else:
                                techniques_[attack_obj.get("name")] = (
                                    technique.Technique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj,
                                    )
                                )

                    else:
                        if not self.subscriptable:
                            techniques_.append(
                                technique.Technique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            techniques_[attack_obj.get("name")] = (
                                technique.Technique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )

        return techniques_

    # -------------------------------------------------------------------------

    @property
    def sub_techniques(
        self,
    ) -> Union[
        List[sub_technique.SubTechnique], Dict[str, sub_technique.SubTechnique]
    ]:
        """
        Get all sub-techniques from the ATT&CK framework.

        Returns:
            List of SubTechnique objects if subscriptable=False, otherwise a
            dictionary mapping sub-technique names to SubTechnique objects.
            Only includes attack patterns that are sub-techniques.
        """
        if self.subscriptable:
            sub_techniques_ = {}
        else:
            sub_techniques_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "attack-pattern":
                if attack_obj.get("x_mitre_is_subtechnique"):
                    if not self.include_deprecated:
                        if not attack_obj.get("x_mitre_deprecated"):
                            if not self.subscriptable:
                                sub_techniques_.append(
                                    sub_technique.SubTechnique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj,
                                    )
                                )
                            else:
                                sub_techniques_[attack_obj.get("name")] = (
                                    sub_technique.SubTechnique(
                                        self.attack_objects,
                                        self.relationships,
                                        self.id_lookup,
                                        **attack_obj,
                                    )
                                )
                    else:
                        if not self.subscriptable:
                            sub_techniques_.append(
                                sub_technique.SubTechnique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            sub_techniques_[attack_obj.get("name")] = (
                                sub_technique.SubTechnique(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )

        return sub_techniques_

    # -------------------------------------------------------------------------

    @property
    def groups(self) -> Union[List[group.Group], Dict[str, group.Group]]:
        """
        Get all groups from the ATT&CK framework.

        Returns:
            List of Group objects if subscriptable=False, otherwise a
            dictionary mapping group names to Group objects.
            Groups represent threat actor organizations and intrusion sets.
        """
        if self.subscriptable:
            groups_ = {}
        else:
            groups_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "intrusion-set":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            groups_.append(
                                group.Group(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            groups_[attack_obj.get("name")] = group.Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                else:
                    if not self.subscriptable:
                        groups_.append(
                            group.Group(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        groups_[attack_obj.get("name")] = group.Group(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return groups_

    # -------------------------------------------------------------------------

    @property
    def software(
        self,
    ) -> Union[List[software.Software], Dict[str, software.Software]]:
        """
        Get all software from the ATT&CK framework.

        Returns:
            List of Software objects if subscriptable=False, otherwise a
            dictionary mapping software names to Software objects.
            Includes both tools and malware.
        """
        if self.subscriptable:
            software_ = {}
        else:
            software_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") in ["tool", "malware"]:
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            software_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            software_[attack_obj.get("name")] = (
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        software_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        software_[attack_obj.get("name")] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return software_

    # -------------------------------------------------------------------------

    @property
    def malware(
        self,
    ) -> Union[List[software.Software], Dict[str, software.Software]]:
        """
        Get all malware from the ATT&CK framework.

        Returns:
            List of Software objects if subscriptable=False, otherwise a
            dictionary mapping malware names to Software objects.
            Only includes objects with type 'malware'.
        """
        if self.subscriptable:
            malware_ = {}
        else:
            malware_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "malware":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            malware_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            malware_[attack_obj.get("name")] = (
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        malware_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        malware_[attack_obj.get("name")] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return malware_

    # -------------------------------------------------------------------------

    @property
    def tools(
        self,
    ) -> Union[List[software.Software], Dict[str, software.Software]]:
        """
        Get all tools from the ATT&CK framework.

        Returns:
            List of Software objects if subscriptable=False, otherwise a
            dictionary mapping tool names to Software objects.
            Only includes objects with type 'tool'.
        """
        if self.subscriptable:
            tools_ = {}
        else:
            tools_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "tool":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            tools_.append(
                                software.Software(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            tools_[attack_obj.get("name")] = software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                else:
                    if not self.subscriptable:
                        tools_.append(
                            software.Software(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        tools_[attack_obj.get("name")] = software.Software(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return tools_

    # -------------------------------------------------------------------------

    @property
    def mitigations(
        self,
    ) -> Union[List[mitigation.Mitigation], Dict[str, mitigation.Mitigation]]:
        """
        Get all mitigations from the ATT&CK framework.

        Returns:
            List of Mitigation objects if subscriptable=False, otherwise a
            dictionary mapping mitigation names to Mitigation objects.
            Includes all course-of-action objects.
        """
        if self.subscriptable:
            mitigations_ = {}
        else:
            mitigations_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "course-of-action":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            mitigations_.append(
                                mitigation.Mitigation(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            mitigations_[attack_obj.get("name")] = (
                                mitigation.Mitigation(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        mitigations_.append(
                            mitigation.Mitigation(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        mitigations_[attack_obj.get("name")] = (
                            mitigation.Mitigation(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )

        return mitigations_

    # -------------------------------------------------------------------------

    @property
    def data_sources(
        self,
    ) -> Union[
        List[data_source.DataSource], Dict[str, data_source.DataSource]
    ]:
        """Get all data sources from the ATT&CK framework.

        Returns:
            List of DataSource objects if subscriptable=False, otherwise a
            dictionary mapping data source names to DataSource objects.
            Includes all x-mitre-data-source objects.
        """
        if self.subscriptable:
            data_sources_ = {}
        else:
            data_sources_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "x-mitre-data-source":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            data_sources_.append(
                                data_source.DataSource(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            data_sources_[attack_obj.get("name")] = (
                                data_source.DataSource(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        data_sources_.append(
                            data_source.DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        data_sources_[attack_obj.get("name")] = (
                            data_source.DataSource(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )

        return data_sources_

    # -------------------------------------------------------------------------

    @property
    def components(
        self,
    ) -> Union[List[component.Component], Dict[str, component.Component]]:
        """
        Get all components from the ATT&CK framework.

        Returns:
            List of Component objects if subscriptable=False, otherwise a
            dictionary mapping data source names to Components objects.
            Includes all x-mitre-component objects.
        """
        if self.subscriptable:
            components_ = {}
        else:
            components_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "x-mitre-data-component":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            components_.append(
                                component.Component(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            components_[attack_obj.get("name")] = (
                                component.Component(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        components_.append(
                            component.Component(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        components_[attack_obj.get("name")] = (
                            component.Component(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )

        return components_

    # -------------------------------------------------------------------------

    @property
    def campaigns(
        self,
    ) -> Union[List[campaign.Campaign], Dict[str, campaign.Campaign]]:
        """
        Get all campaigns from the ATT&CK framework.

        Returns:
            List of Campaign objects if subscriptable=False, otherwise a
            dictionary mapping data source names to Campaign objects.
            Includes all campaign objects.
        """
        if self.subscriptable:
            campaigns_ = {}
        else:
            campaigns_ = []

        for attack_obj in self.attack_objects.get("objects"):
            if attack_obj.get("type") == "campaign":
                if not self.include_deprecated:
                    if not attack_obj.get("x_mitre_deprecated"):
                        if not self.subscriptable:
                            campaigns_.append(
                                campaign.Campaign(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                        else:
                            campaigns_[attack_obj.get("name")] = (
                                campaign.Campaign(
                                    self.attack_objects,
                                    self.relationships,
                                    self.id_lookup,
                                    **attack_obj,
                                )
                            )
                else:
                    if not self.subscriptable:
                        campaigns_.append(
                            campaign.Campaign(
                                self.attack_objects,
                                self.relationships,
                                self.id_lookup,
                                **attack_obj,
                            )
                        )
                    else:
                        campaigns_[attack_obj.get("name")] = campaign.Campaign(
                            self.attack_objects,
                            self.relationships,
                            self.id_lookup,
                            **attack_obj,
                        )

        return campaigns_


# -----------------------------------------------------------------------------


class Error(Exception):

    # -------------------------------------------------------------------------

    def __init__(self, message: str) -> None:
        """
        Initialize the Error exception with a message.

        Args:
            message: The error message to display.
        """
        self.message = message

    def __str__(self) -> str:
        """
        Return the string representation of the error.

        Returns:
            The error message as a string.
        """
        return self.message
