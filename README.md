# AzureFW-HybridOps

This project intends to simplify and improve the user experience of authoring/configuring Azure Firewall Policies and rules.
It provides a two-way sync of rules and configuration allowing hybrid IaC & ClickOps Azure FW policy authoring.

In short the intention is to invent a new "way of working" with Azure Firewalls which I hope is more pleasant than the current OOBE.

# Module installation
```Install-Module -Name AzureFwOps	```

[https://www.powershellgallery.com/packages/AzureFwOps/](https://www.powershellgallery.com/packages/AzureFwOps/)

# How it works

This project utilizes [AzOps](https://github.com/Azure/AzOps) as the IaC backend and aims to mirror the structure that AzOps creates and uses.

At the heart of this project is a powershell module which translates between ``Azure ARM templates`` and ``HybridOps Firewall IaC``

- [AzureFwOps.psm1](/AzureFwOps/AzureFwOps.psm1)

To properly use this module it is recommended to integrate it into your ci/cd pipelines. There are some examples in this repository, but feel free to change and integrate and submit a PR to this repo with more examples

- [Azure DevOps Pipelines](.pipelines/examples/)
- [Github Actions](.github/workflows)

## Azure ARM templates -> HybridOps FW IaC

```
ConvertFrom-ArmFw -ArmFolder $ArmFolder -PolicyFolder $PolicyFolder -Merge
```
The above command reads ARM templates for ``Microsoft.Network/firewallPolicies`` and ``Microsoft.Network/firewallPolicies/ruleCollectionGroups`` resources and generates a easy to read ``policySettings.json`` and csv files that are easy to edit for ApplicationRules, NatRules and NetworkRules.

``$ArmFolder`` is the AzOps resource group folder where Firewall resides.

``$PolicyFolder`` is the folder where you intend to place the HybridOps content.

The switch parameter ``-Merge`` specifies that updates from ARM is merged with any rules written in rule files. This is only recommended if hybrid authoring mode is preferred. For immutable mode is preferred ``-Merge`` should be avoided. 

## HybridOps FW IaC -> Azure ARM templates
```
ConvertTo-ArmFw -ArmFolder $ArmFolder -PolicyFolder $PolicyFolder
```
The above command reads settings from ``PolicyFolder`` and writes to AzOps resource group specified by ``$ArmFolder``. The function is not capbable of creating files on its own nor does it associate policies with firewalls or other policies. See Todo for more information
# Setup More information
## AzOps file structure
```
📂<resourceGroupFolder>
 ┣ 📜microsoft.network_firewallpolicies-<policyName>.json
 ┣ 📜microsoft.network_firewallpolicies_rulecollectiongroups-<policyName>_<ruleCollGroupName>.json
 ┣ ...
 ┗ ...
```

## Firewall HybridOps file structure
```
📦policies
 ┣ 📂<policyName>
 ┃ ┗ 📂<ruleCollGroupName>
 ┃ ┃ ┣ 📂<ruleCollName>
 ┃ ┃ ┃ ┗ 📜ApplicationRule.csv
 ┃ ┃ ┗ 📂<ruleCollName>
 ┃ ┃ ┃ ┗ 📜NetworkRule.csv
 ┃ ┃ ┗ 📂<ruleCollName>
 ┃ ┃ ┃ ┗ 📜NatRule.csv
 ┣ 📂<policyName>
 ┃ ┗...
 ┗ 📜policySettings.json
```
## Rule files and configuration
Headers follow ``FirewallPolicyRule`` objects, [more info in the docs](https://docs.microsoft.com/en-us/azure/templates/microsoft.network/firewallpolicies/rulecollectiongroups?pivots=deployment-language-arm-template#firewallpolicyrule-objects-1).
 At the time of writing AzOps performs a pull using apiVersion "2020-11-01". If the apiVersion adds a type it will automatically get included, albeit unsorted.

### Examples
[policySettings.json](/policies/policySettings.json)

[ApplicationRule.csv](/policies/fwpolicy/rulecollgroup/app-rulecoll/ApplicationRule.csv)

[NetworkRule.csv](/policies/fwpolicy/rulecollgroup/net-rulecoll/NetworkRule.csv)

[NatRule.csv](/policies/fwpolicy/rulecollgroup/net-rulecoll/NatRule.csv)



### policySettings
``policySettings.json`` provides the more static configuration where Policy configuration can be stored, example of configuration defined here is child-policies, RuleCollectionGroup priority settings etc.
It is recommended to generate this file using the ``ConvertFrom-ArmFw`` function once the initial structure is created in Azure Portal.
Be careful with priority when editing this, as deployment will fail if there are conflicting priorities.
[Please refer to Microosft docs for more information on rule-processing](https://docs.microsoft.com/en-us/azure/firewall/rule-processing)

```
[
  {
    "name": "<policyName>",
    "childPolicies": [
      "<resourceId>" // Optional
    ],
    "ruleCollectionGroups": {
      "id": "<resourceId>",
      "name": "<policyName>/<ruleCollGroupName>",
      "priority": 100,
      "ruleCollections": [
        {
          "name": "<ruleCollName>",
          "priority": 200,
          "action": {
            "type": "Deny"
          }
        },
        {
          "name": "<ruleCollName>",
          "priority": 100,
          "action": {
            "type": "Allow"
          }
        }
      ]
    }
  },
]

```


# Assumptions
 - All firewall policies configured exist in the same resource group.
 - To enable two way sync the AzOps Pull pipeline must be run before a push, otherwise it will overwrite changes made in the portal that has not been pulled in.
 - The delimiter should to be ',' This is configurable in the script by setting the var $delimiter in the begin block. space (' ') and semicolon (';') is reserved

# TODO
- Update so that the script can write to fwPolicy files. Currently it cannot associate child fw policies or rulecollectiongroups
- Create fwPolicies by defining them here
- pipeline integration
- videos going step-by-step on how to implement and use
- ~~publish the script as a module in powershell gallery~~
- add whatif output
- add functionality to print rules to console (whatif, writeToArm)