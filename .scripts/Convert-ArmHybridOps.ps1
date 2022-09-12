[cmdletbinding()]
Param(
    $ArmFolder = 'C:\git\AzOps-Accelerator\root\frk4-avanade (4d0765d1-ab75-4420-b750-2fafe654e5a9)\firewall',
    $PolicyFolder = 'C:\git\AzureFW-HybridOps\policies',
    [Switch]$Merge
)
Begin{
    # Formats JSON in a nicer format than the built-in ConvertTo-Json does.
    # Thanks to Kody for providing this excellent function (https://stackoverflow.com/users/1754995/kody)
    # https://stackoverflow.com/questions/57329639/powershell-convert-to-json-is-bad-format/57329852#57329852
    function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
        $indent = 0;
        ($json -Split '\n' |
        % {
            if ($_ -match '[\}\]]') {
            # This line contains  ] or }, decrement the indentation level
            $indent--
            }
            $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
            if ($_ -match '[\{\[]') {
            # This line contains [ or {, increment the indentation level
            $indent++
            }
            $line
        }) -Join "`n"
    }
}
Process{
    #Read arm settings and update before merging
    If($Merge){
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
                "linkedRuleCollectionGroups" = @($thisPolicy.properties.ruleCollectionGroups)
                "ruleCollectionGroups" = @()
            }
        }
        
        #Assert folders for firewall and rule coll groups
        # DO I NEED THIS? I think so since ruleCollGroups are unique per policy, right?
        $policies | Foreach-Object{
            $policyName = $_.name
            New-Item "$PolicyFolder\$policyName" -ItemType Directory -Force
            Try{
                $_.ruleCollectionGroups | Foreach-object{
                    New-Item "$PolicyFolder\$policyName\$($_.id.split('/')[-1])" -ItemType Directory -Force
                }
            }
            Catch{}
        }

        #Process all rule collection groups
        $ruleCollectionGroups = @()
        $resources | Where-Object {$_.type -eq 'Microsoft.Network/firewallPolicies/ruleCollectionGroups'} | Foreach-object{
            $thisRuleCollGroup = $_
            $object = [PSCustomObject]@{
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
            If($thisPolicy.linkedRuleCollectionGroups.id.count -gt 0){
                $thisRuleCollGroupId = $thisPolicy.linkedRuleCollectionGroups.id | Where-Object{$_.split('/')[-1] -eq $thisRuleCollGroup.name.Split('/')[-1]}
                $object = [PSCustomObject]@{
                    "id" = $thisRuleCollGroupId
                    "name" = $thisRuleCollGroup.name
                    "priority" = $thisRuleCollGroup.priority
                    "ruleCollections" = $thisRuleCollGroup.ruleCollections
                }
                $thisPolicy.ruleCollectionGroups = $object
            }
        }
        #Save everything, except linkedRuleCollectionGroups as they are also part of the member ruleCollectionGroups
        $policies | Select-object -Property * -ExcludeProperty linkedRuleCollectionGroups | ConvertTo-Json -Depth 100 | Format-Json | Out-File $PolicyFolder\policySettings.json -Encoding utf8 -Force

        
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
}
End{}
