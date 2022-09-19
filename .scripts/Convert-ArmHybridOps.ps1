[cmdletbinding()]
Param(
    $ArmFolder,
    $PolicyFolder
)
Begin{
    <#
    .\.scripts\Convert-ArmHybridOps.ps1 -ArmFolder 'C:\git\AzOps-Accelerator\root\frk4-avanade (4d0765d1-ab75-4420-b750-2fafe654e5a9)\firewall' -PolicyFolder 'C:\git\AzureFW-HybridOps\policies'
    #Testing
    $ArmFolder = 'C:\git\AzOps-Accelerator\root\frk4-avanade (4d0765d1-ab75-4420-b750-2fafe654e5a9)\firewall' 
    $PolicyFolder = 'C:\git\AzureFW-HybridOps\policies'
    #>

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

    Function ConvertFrom-ArmFw {
    Param(
        $ArmFolder,
        $PolicyFolder
    )
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

        #Assert folders for firewall and ruleCollGroups
        $policies | Foreach-Object {
            $policyName = $_.name
            New-Item "$PolicyFolder\$policyName" -ItemType Directory -Force
            Try{
                $_.ruleCollectionGroups | Foreach-object{
                    $ruleCollGroup = $_.name.split('/')[-1]
                    New-Item "$PolicyFolder\$policyName\$ruleCollGroup" -ItemType Directory -Force
                    $_.ruleCollections | Foreach-Object{
                        New-Item "$PolicyFolder\$policyName\$ruleCollGroup\$($_.name)" -ItemType Directory -Force
                    }
                }
            }
            Catch{}
        }
        
        #Create CSV files, one per folder.
        $resources | Where-Object {$_.type -eq 'Microsoft.Network/firewallPolicies/ruleCollectionGroups'} | Foreach-object{
            $thisRuleCollGroup = $_
            $thisRuleCollGroup.properties.ruleCollections | Foreach-Object{
                $ruleColl = $_
                If($ruleColl.rules.count -ge 1){
                    $thisCsvFile = "$PolicyFolder\$($thisRuleCollGroup.name)\$($ruleColl.name)\$($ruleColl.rules[0].ruleType).csv"
                    
                    # We sort the output for readability. This might cause issues if apiVersion breaks it. Just use default then.
                    # https://docs.microsoft.com/en-us/azure/templates/microsoft.network/firewallpolicies/rulecollectiongroups?pivots=deployment-language-arm-template#firewallpolicyrule-objects-1
                    Switch($ruleColl.rules[0].ruleType){
                        "ApplicationRule"{
                            $headers = 'name','ruleType','destinationAddresses','fqdnTags','protocols','sourceAddresses','sourceIpGroups','targetFqdns','targetUrls','terminateTLS','webCategories'
                        }
                        "NatRule"{
                            $headers = 'name','ruleType','destinationAddresses','destinationPorts','ipProtocols','sourceAddresses','sourceIpGroups','translatedAddress','translatedFqdn','translatedPort'
                        }
                        "NetworkRule"{
                            $headers = 'name','ruleType','destinationAddresses','destinationFqdns','destinationIpGroups','destinationPorts','ipProtocols','sourceAddresses','sourceIpGroups'
                        }
                        Default{ #Auto sorting
                            Write-Warning "No sorting found for type:'$($ruleColl.rules[0].ruleType)'. Applying auto sorting"
                            $headers = 0..($ruleColl.rules.count-1) | Foreach-object{$ruleColl.rules[$_] | get-member -membertype NoteProperty | Select-Object -ExpandProperty Name} | Select-Object -unique | Sort-Object
                        }
                    }
                    $headers -join ',' | out-file $thisCsvFile
                    $propertiesExpression = "`"$(($headers | Foreach-object{'$($_.{0})' -f $_}) -join ',')`""
                    $ruleColl.rules | Foreach-object{(Invoke-Expression $propertiesExpression)}  | out-file $thisCsvFile -append
                }
            }
        }
    }

    Function ConverTo-ArmFw {
    Param(
        $ArmFolder,
        $PolicyFolder,
        $fwPolicyFileFormat = 'microsoft.network_firewallpolicies-{0}.json',
        $fwRuleCollGroupFileFormat = 'microsoft.network_firewallpolicies_rulecollectiongroups-{0}_{1}.json'
    )
        #Read all policy files
        $settings = Get-Item -LiteralPath "$PolicyFolder\policySettings.json" | Get-Content | ConvertFrom-Json
        $ruleFiles = Get-ChildItem -LiteralPath $PolicyFolder -Recurse -File -filter "*.csv"
        
        #Get all files in firewall folder
        $rgFiles = Get-ChildItem -LiteralPath $ArmFolder
        #microsoft.network_firewallpolicies-fwpolicy
        #microsoft.network_firewallpolicies_rulecollectiongroups-fwpolicy_rulecollgroup.json

        #Write settings to ARM Templates
        $settings | ForEach-Object{
            $thisFwPolicy = $_
            $fwPolicyFile = $fwPolicyFileFormat -f $thisFwPolicy.name
            
            #Write fwPolicy files
            #Create new files if none exist
            If(-not($rgFiles.Name -contains $fwPolicyFile)){
                Throw "This script can't handle creation of new ARM files yet! Please create a PR on https://github.com/Freakling/AzureFW-HybridOps to fix this."
            }
            #$fwPolicyData = Get-content "$ArmFolder\$fwPolicyFile" | ConvertFrom-Json
            #LETS DO THIS LATER

            #Write csv files
            $settings.ruleCollectionGroups | Foreach-Object{
                $thisRuleCollGroup = $_
                $ruleCollGroupFile = $fwRuleCollGroupFileFormat -f $thisFwPolicy.name,$($thisruleCollGroup.name.split('/')[-1])
                
                #Create new files if none exist
                If(-not($rgFiles.Name -contains $ruleCollGroupFile)){
                    Throw "This script can't handle creation of new ARM files yet! Please create a PR on https://github.com/Freakling/AzureFW-HybridOps to fix this."
                }
                
                $ruleCollGroupData = Get-content "$ArmFolder\$ruleCollGroupFile" | ConvertFrom-Json
                $thisArmResource = $ruleCollGroupData.resources | Where-object {$_.name -eq $thisRuleCollGroup.name}
                
                #set properties
                $thisArmResource.properties.priority = $thisRuleCollGroup.priority
                
                #process each rule coll and write them to arm code
                # https://learn.microsoft.com/en-us/azure/templates/microsoft.network/firewallpolicies/rulecollectiongroups?pivots=deployment-language-arm-template
                $thisRuleCollGroup.ruleCollections | Foreach-Object{
                    $thisRuleColl = $_
                    $thisArmRuleColl = $thisArmResource.properties.ruleCollections | Where-Object{$_.name -eq $thisRuleColl.name}
                    
                    #If no ruleCollection exists then
                    If(-not($thisArmRuleColl)){
                        Throw "This script can't create ruleCollections yet. Create a blank rulecoll until this is fixed. Please create a PR on https://github.com/Freakling/AzureFW-HybridOps to fix this."
                    }

                    #write settings to rulecoll
                    $thisArmRuleColl.priority = $thisRuleColl.priority
                    $thisArmRuleColl.action = $thisRuleColl.action
                    
                    #read rules from csv
                    $csvFiles = Get-ChildItem "$policyFolder/$($thisRulecollGroup.name)/$($thisRuleColl.name)"

                    $theseRules = @()
                    #set all rules
                    $csvFiles | Foreach-object{
                        $file = $_

                        $type = $file.Name -replace '.csv',''
                        switch($type){
                            "ApplicationRule"{
                                #$headers = 'name','ruleType','destinationAddresses','fqdnTags','protocols','sourceAddresses','sourceIpGroups','targetFqdns','targetUrls','terminateTLS','webCategories'
                            }
                            "NatRule"{
                                #$headers = 'name','ruleType','destinationAddresses','destinationPorts','ipProtocols','sourceAddresses','sourceIpGroups','translatedAddress','translatedFqdn','translatedPort'
                            }
                            "NetworkRule"{
                                #$headers = 'name','ruleType','destinationAddresses','destinationFqdns','destinationIpGroups','destinationPorts','ipProtocols','sourceAddresses','sourceIpGroups'
                            }
                            Default{ #Auto sorting
                                throw "Can't process $($file.name)"
                            }
                        }
                    }
                    $thisArmruleColl.rules[0]

                }
                
                $thisArmResource
                $thisRuleCollGroup

                $ruleCollGroupData

            }

        }
        #Write settings to rulecollectiongroups
        $ruleColls | ForEach-Object{
            $thisColl = $_
            
        }

    }
}
Process{
    #Read arm settings and update before merging
    ConvertFrom-ArmFw -ArmFolder $ArmFolder -PolicyFolder $PolicyFolder
}
End{}
