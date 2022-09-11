[cmdletbinding()]
Param(
    $ArmFolder = 'C:\git\AzOps-Accelerator\root\frk4-avanade (4d0765d1-ab75-4420-b750-2fafe654e5a9)\firewall',
    $PolicyFolder = 'C:\git\AzureFW-HybridOps\policies',
    [Switch]$Merge
)


function Clear-WhiteSpace{
Param(
[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    $Text
)
    "$($Text -replace "(`t|`n|`r)"," " -replace "\s+"," ")".Trim()
}
#Read arm settings and update before merging
If($Merge){
    
    #$connections
    
    #Extract all resources from ARM files
    $resources = @()
    Get-ChildItem -LiteralPath $ArmFolder -filter *.json | Foreach-Object{
        $resources += [array](Get-Content $_.FullName | ConvertFrom-Json).resources
    }
    
    #Process all firewall policies and store in policies object (stored in policySettings.json)
    $policies = @()
    $resources | Where-Object {$_.type -eq 'Microsoft.Network/firewallPolicies'} | Foreach-object{
        $thisPolicy = $_
        $policies += [pscustomobject]@{
            "name" = $thisPolicy.name
            "childPolicies" = @($thisPolicy.properties.childpolicies.id)
            "ruleCollectionGroups" = @($thisPolicy.properties.ruleCollectionGroups)
        }
    }
    
    #Assert folders for firewall and rule coll groups
    # DO I NEED THIS? I think so since ruleCollGroups are unique per policy, right?
    #$policies | Foreach-Object{
    #    $policyName = $_.name
    #    New-Item "$PolicyFolder\$policyName" -ItemType Directory -Force
    #    Try{
    #        $_.ruleCollectionGroups | Foreach-object{
    #            New-Item "$PolicyFolder\$policyName\$($_.id.split('/')[-1])" -ItemType Directory -Force
    #        }
    #    }
    #    Catch{}
    #}

    #Process all rule collection groups
    $ruleCollectionGroups = @()
    $resources | Where-Object {$_.type -eq 'Microsoft.Network/firewallPolicies/ruleCollectionGroups'} | Foreach-object{
        $thisRuleCollGroup = $_
        $object += [PSCustomObject]@{
            "name" = $thisRuleCollGroup.name
            "priority" = $thisRuleCollGroup.properties.priority
            "ruleCollections" = @()
        }
        $thisRuleCollGroup.properties.ruleCollections | Foreach-object {
            $object.ruleCollections += [pscustomobject]@{
                "name" = $_.name
                "priority" = $_.priority
                "action" = $_.action
            }
        }
        $ruleCollectionGroups += $object
    }
    
    #join ruleCollectionGroups and policies (in order to generate a policySettings.json)
    $policies | ForEach-Object{
        $thisPolicy = $_
        $thisRuleCollGroup = $ruleCollectionGroups | Where-Object{$_.name.split('/')[0] -eq $thisPolicy.name}
        $thisRuleCollGroupId = $thisPolicy.ruleCollectionGroups.id | Where-Object{$_.split('/')[-1] -eq $thisRuleCollGroup.name.Split('/')[-1]}
        $object = [PSCustomObject]@{
            "id" = $thisRuleCollGroupId
            "name" = $thisRuleCollGroup.name
            "priority" = $thisRuleCollGroup.priority
            "ruleCollections" = $thisRuleCollGroup.ruleCollections
        }
        $thisPolicy.ruleCollectionGroups = $object
    }
    $policies | ConvertTo-Json -depth 100 | Out-File $PolicyFolder\policySettings.json -Encoding utf8 -Force

    #$FwFiles | Foreach-object{
    #    $thisContent = Get-Content $_.FullName | ConvertFrom-Json
    #    $thisContent.resources | Foreach-Object{
    #        $resource = $_
    #        Switch($resource.type){
    #            "Microsoft.Network/firewallPolicies/ruleCollectionGroups" {
    #                #all good
    #            }
    #            default {
    #                Throw "Script cant handle $($resource.type)"
    #            }
    #        }
    #        $resource.properties.ruleCollections
    #    }
    #}

}