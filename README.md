# AzureFW-HybridOps

This project intends to simplify and improve the user experience of authoring/configuring Azure Firewall Policies and rules.
It provides a two-way sync of rules and configuration allowing hybrid IaC & ClickOps Azure FW policy authoring.

## How it works

This project utilizes AzOps as the IaC backend and aims to mirror the structure that AzOps creates.

### AzOps file structure
```
📂<resourceGroupFolder>
 ┣ 📜microsoft.network_firewallpolicies-<policyName>.json
 ┣ 📜microsoft.network_firewallpolicies_rulecollectiongroups-<policyName>_<ruleCollGroupName>.json
```

#### Firewall HybridOps file structure
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
### Rule files and configuration
Headers follow ``FirewallPolicyRule`` objects, [more info in the docs](https://docs.microsoft.com/en-us/azure/templates/microsoft.network/firewallpolicies/rulecollectiongroups?pivots=deployment-language-arm-template#firewallpolicyrule-objects-1).
 At the time of writing AzOps performs a pull using apiVersion "2020-11-01". If the apiVersion adds a type it will automatically get included, albeit unsorted.

#### ApplicationRule.csv
```
name,ruleType,destinationAddresses,fqdnTags,protocols,sourceAddresses,sourceIpGroups,targetFqdns,targetUrls,terminateTLS,webCategories
```
##### NetworkRule.csv
```
name,ruleType,destinationAddresses,destinationFqdns,destinationIpGroups,destinationPorts,ipProtocols,sourceAddresses,sourceIpGroups
```
##### NatRule.csv
```
name,ruleType,destinationAddresses,destinationPorts,ipProtocols,sourceAddresses,sourceIpGroups,translatedAddress,translatedFqdn,translatedPort
```
#### policySettings.json

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


Assumptions:
 - All firewall policies configured exist in the same resource group.
 - To enable two way sync the AzOps Pull pipeline must be run before a push, otherwise it will overwrite changes made in the portal that has not been pulled in.
