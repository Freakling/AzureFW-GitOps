# AzureFW-HybridOps

This project intends to simplify and improve the user experience of authoring/configuring Azure Firewall Policies and rules.
It provides a two-way sync of rules and configuration allowing hybrid IaC & ClickOps Azure FW policy authoring.

In short the intention is to invent a new "way of working" with Azure Firewalls which I hope is more plesant than the current OOBE.

## How it works

This project utilizes [AzOps](https://github.com/Azure/AzOps) as the IaC backend and aims to mirror the structure that AzOps creates and uses.

At the heart of this project is a powershell scripts which translates between ``Azure ARM templates`` and ``HybridOps FW IaC``

- [Convert-ArmHybridOps.ps1](.scripts/Convert-ArmHybridOps.ps1)

To properly use this script it is recommended to integrate it into your ci/cd pipelines. There are some examples in this repository, but feel free to change and integrate and submit a PR to this repo with more examples

- [Azure DevOps Pipelines](.devops)
- [Github Actions](.github/workflows)

### Azure ARM templates -> HybridOps FW IaC

# Setup/More information
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

### ``ApplicationRule.csv``
```
name,ruleType,destinationAddresses,fqdnTags,protocols,sourceAddresses,sourceIpGroups,targetFqdns,targetUrls,terminateTLS,webCategories
```
#### Example
### ``NetworkRule.csv``
```
name,ruleType,destinationAddresses,destinationFqdns,destinationIpGroups,destinationPorts,ipProtocols,sourceAddresses,sourceIpGroups
```
#### Example
### ``NatRule.csv``
```
name,ruleType,destinationAddresses,destinationPorts,ipProtocols,sourceAddresses,sourceIpGroups,translatedAddress,translatedFqdn,translatedPort
```
#### Example
### ``policySettings.json``
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

# Features to add
Create fwPolicies by defining them here

