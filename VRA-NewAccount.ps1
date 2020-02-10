Function AuthenticateWithVRA {
    #RefreshToken is generated in VRA GUI. 
    # - Login as an admin - browse to 'my account' - select API Tokens. 
    # - Generate a new token. 
    # 
    $refreshToken = "<your Refresh Token from VRA>"
    $body = "refresh_token=$refreshToken"
    $GetMyToken = Invoke-webrequest -Uri "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize" -Method POST -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -Body $body
    $MyAccessToken = ($GetMyToken | convertFrom-json).access_token
    return @{"Authorization"="Bearer $MyAccessToken"}
}

function Get-APIData {
    [CmdLetBinding()]
param(
	[parameter(Mandatory=$true)]
    [string]$URIBit,
    [parameter(Mandatory=$false)][alias('fk')]
    [string]$FilterKey,
    [parameter(Mandatory=$false)][alias('fv')]
    [string]$FilterValue,
    [parameter(Mandatory=$false)][alias('fk2')]
    [string]$FilterKey2,
    [parameter(Mandatory=$false)][alias('fv2')]
    [string]$FilterValue2

)
    #create a search filter if both values provided.
    if ("" -ne $FilterValue -and "" -ne $FilterKey) {
        $SearchFilter = "("+$FilterKey+" eq '"+$FilterValue+"')"      
    } else {
        Write-Verbose "no variables found"
        $SearchFilter = $null
    }
    if (("" -ne $FilterValue2 -and "" -ne $FilterKey2) -and ($null -ne $searchFilter)) {
        $SearchFilter += " and ("+$FilterKey2+" eq '"+$FilterValue2+"')"
    } 
    Write-Verbose $("sf:"+$SearchFilter)
    $apiURL = $("https://api.mgmt.cloud.vmware.com" + $URIBit).replace("\","/")
    if  ($null -ne $SearchFilter) {  # $SearchFilter = (name eq 'My Cloud Account Name')
        $apiURL += "?`$filter="+$SearchFilter
    }
    Write-verbose "url:"
    write-verbose $apiURL
    $Results = Invoke-RestMethod -Uri $apiURL -Method get -ContentType "application/json" -UseBasicParsing -headers $headers;
    if ($null -eq $results.content) {
        #exampl: '/iaas/api/network-profiles/{id}' will return that specific network object's results here..
        return $results  
    } else {
        #example: '/iaas/api/network-profiles'  - will return all network profiles here:
        return $results.content 
    }
}

$headers = AuthenticateWithVRA;
$FindcloudAccount = Get-APIData -uribit '/iaas/api/cloud-accounts-aws' | where-object{$_.accessKeyId -eq $strCloudAccountAccessKey}
#If not, create a new cloud account for this user. 
if ($null -eq $FindcloudAccount) { #drop out of script if cloud account does not exist or failed to create. 
    $Newcloudaccount = @{"accessKeyId"=$strCloudAccountAccessKey;"secretAccessKey"=$strCloudAccountSecretKey;"createDefaultZones"="true";"name"=$strCloudAccountName;"regionIds"=$CloudRegionArray;"tag"=@(@{"key"="ca";"value"=$($strCloudAccountName+"-aws")})} 
    $cloudaccountjson = $Newcloudaccount | ConvertTo-Json
    $CAResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/cloud-accounts-aws" -Method POST -ContentType "application/json" -headers $headers -Body $cloudaccountjson
}   

$FindExistingCloudZones = Get-APIData -uri '/iaas/api/zones' -filterkey "name" -FilterValue $($FindcloudAccount.name+"*")
#Tag each CloudZone with a tag for this cloud-account combination
ForEach ($ThisCZ in $FindExistingCloudZones) {
    if ($null -eq ($ThisCZ.tags | Where-Object{$_.key -eq "cz"})) {
        $CZRegion=$(get-apidata $thiscz._links.region.href).externalRegionId
        $CZTagValue = $FindcloudAccount.name + "-aws-" + $CZRegion.ToLower()
        $CZTags = @{"name"=$ThisCZ.name;"tags"=@(@{"key"="cz";"value"=$CZTagValue})} | ConvertTo-Json
        $CZURL = "https://api.mgmt.cloud.vmware.com/iaas/api/zones/"+$ThisCZ.id
        Invoke-RestMethod -uri $CZURL -Method PATCH -ContentType "application/json" -UseBasicParsing -headers $headers -Body $CZTags
    }
}
#########################   tag each Availability Zone for each Cloud Zone  ############################# 
#Find all the compute objects that are availability zones for current cloud account
### NEED TO ESCAPE THE $ BEFORE 'FILTER' OR IT FAILS!! 
$azURL = "/provisioning/uerp/provisioning/mgmt/compute?expand&`$filter=((type eq 'ZONE') and (endpoint.name eq '"+$FindcloudAccount.name+"'))"
$AZs = Get-APIData $azURL
#loop through endpoints to se which match my found AZs.
ForEach ($azLink in $azs.DocumentLinks) {        
    $FoundAZ = $AZs.documents.$azLink | select-object name, documentSelfLink, expandedTags
    if ($null -ne $FoundAZ) {
        $newAZTagValue = $FindcloudAccount.name +"-aws-"+ $FoundAZ.name
        if ($FoundAZ.expandedTags.count -gt 0) {
            $FindNewAZTag = (($FoundAZ.expandedTags.tag.split("\n") -match $newAZTagValue).count -gt 0)
        } else {$FindNewAZTag = $false } # no tags exist on availability zone}
        if (!$FindNewAZTag ) {   
            $newAZtagJSON = @{"tagsToAssign" = @(@{"key"="az";"value"=$newAZTagValue});"resourceLink"=$FoundAZ.documentSelfLink} | ConvertTo-Json
            $AZTaggingResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/provisioning/uerp/provisioning/mgmt/tag-assignment" -Method POST -ContentType "application/json" -headers $headers -Body $newAZtagJSON
            $ResultsDetails += $AZTaggingResults
        } else {
            write-verbose $("this availability zone is already tagged correctly"+$newAZTagValue+$newaz.expandedTags.tag)
        }        
    } else {
        $ResultsDetails += "no zones were found, could not apply tagging."
    }     
}


