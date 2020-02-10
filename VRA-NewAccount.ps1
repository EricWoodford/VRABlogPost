F<# .SYNOPSIS
     VRA New Account Deployment
.DESCRIPTION
     Script uses the the VRA web API to build the user interface for a new customer-project
        - Creates new AWS Cloud Account + Cloud Zones 
            = requires CloudAccountName, Access Key and Secret Key 
        - Creates a new project based off the Cloud Account info
        - Creates network profiles for each AWS AZ deployed into (US-WEST-1 and US-WEST-2)
            = tag fabric network in network profiles "CloudAccountName_US-WEST-1_Test/Dev/Prod"
        - Creates new image mappings based off the 'dev' account defined. 
        - Add new cloud account to the each of the flavor mappings similar to dev account. 
        - Create new storage profiles based off new cloud account + AZs that dev account is in.
.CHANGES
    - 12/17/19 added filtering to API calls to speed up requests.   
    - 12/19/19 added fabric network tagging = Linux, us-west-2[1] = Windows
    -          us-west-2[0]=projectName_aws_test_Linux
    -          us-west-2[1]=projectName_aws_test_Windows
.NOTES
     Author     : Cloud Automation & Orchestration team - Eric Woodford
     		  ref: www.ericwoodford.com
.EXAMPLES
#>
[CmdLetBinding()]
param(
    [parameter(Mandatory=$true,position=1)]
    [string]$strCloudAccountName, 
    [parameter(Mandatory=$true,position=2)]
    [string]$strCloudAccountAccessKey, 
    [parameter(Mandatory=$true,position=3)]
    [string]$strCloudAccountSecretKey
)

# VRA Dev Account ID -> Script copies this account for new customers to be.
$DevAccountID = '123123123123123123123' 
#Project admins and members for this new project. 
$DefaultAdminSMTP = @('admin1@example.com','admin2@example.com') 
$DefaultMemberSMTP = @('tech1@example.com','tech2@example.com','tech3@example.com')
#AWS Regions that this cloud account will include.
$CloudRegionArray = @("us-west-2") 
#global variable to be used throughout for tracking errors. 
$returnErrorCode = 0
$ResultsDetails = @()


#remove spaces from cloud account name. 
$strCloudAccountName = $strCloudAccountName.replace(" ","_")
$ResultsDetails += $strCloudAccountName

Function AuthenticateWithVRA {
    #RefreshToken is generated in VRA GUI. 
    # - Login as an admin - browse to 'my account' - select API Tokens. 
    # - Generate a new token. 
    # 
    $refreshToken = "<64 digit long refresh token generated from your VRA account>"
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
    $headers = AuthenticateWithVRA
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


########################## Verify Authentication Parameters working correctly.  ####################
$headers = AuthenticateWithVRA 
if ($null -eq $headers.Authorization -or $headers.Authorization.Length -lt 20 )  {write-error "ERROR: not authenticated with VRA.";exit}
$testAbout = get-apidata -URIBit "/iaas/api/about";$apiVersion = $testAbout.latestApiVersion
if($null -eq $testAbout.latestApiVersion) {write-error "ERROR: not authenticated with VRA.";exit}
########################### VERIFY DEV ACCOUNT EXISTS ################################
$findDevAccount = get-apidata -URIBit $("/iaas/api/cloud-accounts-aws/"+$DevAccountID )
if ($null -eq $findDevAccount -or $findDevAccount -is [array]) {
    Write-Error "Dev Account not found, please update the variable `$devAccountID with a valid account id."
    $ResultsDetails += "Dev Account not found:"+$DevAccountID
    Exit
} else {
    $ResultsDetails += "Dev Cloud Account Found:" 
    $resultsDetails += $findDevAccount
}
################################ Create Cloud Account and Cloud Zones for new Account ############################
write-verbose "see if this cloud account has already been added to vra."
$FindcloudAccount = Get-APIData -uribit '/iaas/api/cloud-accounts-aws' | where-object{$_.accessKeyId -eq $strCloudAccountAccessKey}
#If not, create a new cloud account for this user. 
if ($null -eq $FindcloudAccount) { #drop out of script if cloud account does not exist or failed to create. 
    # create cloud account    
    $Newcloudaccount = @{"accessKeyId"=$strCloudAccountAccessKey;"secretAccessKey"=$strCloudAccountSecretKey;"createDefaultZones"="true";"name"=$strCloudAccountName;"regionIds"=$CloudRegionArray;"tag"=@(@{"key"="ca";"value"=$($strCloudAccountName+"-aws")})} 
    $cloudaccountjson = $Newcloudaccount | ConvertTo-Json
    $CAResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/cloud-accounts-aws" -Method POST -ContentType "application/json" -headers $headers -Body $cloudaccountjson
    $ResultsDetails += $CAResults
    if  ($null -eq $CAResults) {
        $returnErrorCode = 1
    }
    $failCounter = 0    
    Do {
        #validate new cloud account created.. If doesn't exist after 10 queries, then exit script
        $FindcloudAccount = Get-APIData -uribit '/iaas/api/cloud-accounts-aws' | where-object{$_.accessKeyId -eq $strCloudAccountAccessKey}
        $failCounter ++
    } while ($null -eq $FindcloudAccount -and $failCounter -lt 10)
    
} else {
   write-verbose "A cloud account with this name already exists." 
   $ResultsDetails += $FindcloudAccount
   # Replace entered name, existing cloud account name
   $strCloudAccountName = $FindcloudAccount.name  
}
if ($failCounter -ge 9) {$returnErrorCode = 9;Write-Error "New Cloud Account Cannot be found after creation.";exit} 
else {    # Drop completely out of script if cloud-account fails to create. 
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

    #######################  Create new project / modify existing project ###############################
    #
    $FindExistingProject = Get-APIData -uri '/iaas/api/projects' -FilterKey "name" -filtervalue $FindcloudAccount.name
    if ($null -eq $FindExistingProject) {        
        $zonejson = @();$emailJSON=@();$memberEmailJSON = @()
        foreach ($zone in $FindExistingCloudZones) { $zonejson += @{"zoneId"=$zone.id;"maxNumberInstances"=50;"priority"=0}  }
        #email addresses defined as global variable at tome.
        ForEach ($email in $DefaultAdminSMTP | sort-object -Unique ) { $emailJSON += @{"email"=$email } }    
        ForEach ($email in $DefaultMemberSMTP| sort-object -Unique ) { $memberEmailJSON += @{"email"=$email } }    
        
        $newProject = @{"name"=$FindcloudAccount.name;"description"=$((get-date).ToLongDateString());"administrators"=$emailJSON;"members"=$memberEmailJSON;"zoneAssignmentConfigurations"=$zonejson}
        $newProjectJSON = $NewProject | ConvertTo-json -Depth 4
        $NProjResults=Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/projects" -Method POST -ContentType "application/json" -UseBasicParsing -headers $headers -Body $newProjectJSON
        if ($null -eq $NProjResults) { $returnErrorCode += 1}
        $ResultsDetails += $NProjResults

        do {
            $FindExistingProject = Get-APIData -uri '/iaas/api/projects' -FilterKey name -filtervalue $FindcloudAccount.name
        } while ($null -eq $FindExistingProject )
    } else {
        #write-verbose "Project with this name already exists."
        $ResultsDetails += $FindExistingProject
    }

    if ($null -eq (Get-APIData -uri '/iaas/api/projects' -FilterKey name -FilterValue $FindcloudAccount.name)) {
        write-error "ERROR: Project not created."
        exit}

    ###############################BUILD IMAGE PROFILES ################################
    write-verbose  "Building image profiles based on source/dev account: " #,$DevAccountID    
    $headers = AuthenticateWithVRA
    #Get DevSandbox Regions, Copy their flavor and image mappings to the new cloud account
    $MyDevSandboxRegions = Get-APIData -URIBit /iaas/api/regions -FilterKey "cloudAccountId" -FilterValue $DevAccountID
    #Find regions associated with new cloud account, these are originally defined by static variable $CloudRegionArray
    $NewCARegions = Get-APIData -URIBit /iaas/api/regions -FilterKey "cloudAccountId" -FilterValue $FindcloudAccount.id
    if ($null -eq $MyDevSandboxRegions -or $null -eq $NewCARegions) {write-error "No or Incomplete Region info available.";exit}
    
    #delete image profiles that exist already for this account. 
    $apiVersion = (Get-APIData /iaas/api/about).latestApiVersion
    [array]$FindEImageProfile = Get-APIData '/iaas/api/image-profiles' -FilterKey name -FilterValue $FindcloudAccount.name 
    ForEach ($FoundImageProfile in $FindEImageProfile) {    
        Write-Verbose "found duplicate image profiles, going to delete and recreate them."
        $deleteImageProfileURL = "https://api.mgmt.cloud.vmware.com/iaas/api/image-profiles/"+$FoundImageProfile.id+ "?apiVersion="+$apiVersion
        Invoke-WebRequest -uri $deleteImageProfileURL -Method DELETE -ContentType "application/json" -UseBasicParsing -headers $headers
    }
    Write-Verbose "Building OS Hashtable from existing Dev enviroment"
    $ImageHash = @{}
    ForEach ($region in $MyDevSandboxRegions) {        
        $ProdRegionImageProfiles = Get-APIData -uribit '/iaas/api/image-profiles' | Where-Object{$_._links.region.href -eq $region._links.self.href}
        if ($null -ne $ProdRegionImageProfiles) {
            $ImageHash[$region.externalRegionId] = @{}
            $CurrentlyMappedImageProfiles = $ProdRegionImageProfiles.imagemappings.mapping | get-member -membertype noteproperty | select-object -ExpandProperty name
            #Loop through each Image for this region (could be multiple OS options done here)
            Foreach ($IFlvr in $CurrentlyMappedImageProfiles ) {
                $ImageID     = $ProdRegionImageProfiles.imagemappings.mapping.$IFlvr.id
                $ImageName   = $ProdRegionImageProfiles.imagemappings.mapping.$IFlvr.name                                
                $ImageHash[$region.externalRegionId] += @{$IFlvr=@{"name"=$ImageName;"id"=$ImageID}}  
            } 
        }
    }      
    #Create the Image profiles for all regions.
    ForEach ($newRegion in $NewCARegions) {
        #Find the region in DevSandbox, that matches the current region for the new Cloud Account
        if ($null -ne $ImageHash[$newRegion.externalRegionId] ) {                
            #write-host "create:"+$thisNewRegion.externalRegionId
            $CreateNewImageProfile = @{"regionId"=$newRegion.id;"name"=$FindcloudAccount.name;"imageMapping"=$ImageHash[$newRegion.externalRegionId]} | ConvertTo-Json -Depth 3 -Compress                
            $ResultsDetails += $CreateNewImageProfile  
            $IPResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/image-profiles" -Method POST -ContentType "application/json" -UseBasicParsing -headers $headers -Body $CreateNewImageProfile            
            $ResultsDetails += $IPResults                
            if ($null -eq $IPResults) { $returnErrorCode += 1;Exit }
        }
    }
    #####################################  Loop Flavor mappings ####################################
    $headers = AuthenticateWithVRA
   #$Static_AllTheFlavors = @("t2.micro","t2.nano","t2.small","t2.medium","t2.large","t2.xlarge","t2.2xlarge",`
    #                  "m5a.xlarge","m5a.2xlarge","m5a.4xlarge","m5a.8xlarge","m5a.large",`
    #                  "c5.large","c5.xlarge","c5.2xlarge","c5.4xlarge","c5.9xlarge",`
    #                  "r5.large","r5.xlarge","r5.2xlarge","r5.4xlarge","r5.8xlarge",`
    #                  "t3.micro","t3.nano","t3.small","t3.medium","t3.large","t3.xlarge") | Sort-Object
    $DevFlavorMapping =foreach ($devRegion in $MyDevSandboxRegions) {
         Get-APIData /iaas/api/flavors  | ?{$_._links.region.href -eq $devRegion._links.self.href}
    }
    $AllTheFlavors = $DevFlavorMapping.mapping | get-member -membertype noteproperty | select-object -ExpandProperty name -Unique
 
    #Builds the flavor mapping JSON object. 
    $FlavorArray = @{}
    ForEach ($ThisFlavor in $AllTheFlavors) {       
        $FlavorArray += @{$ThisFlavor=@{"name"=$ThisFlavor}}   #AWS Flavor mappings are basically t2.small=t2.small. this will need to be more complex when we bring on other services. 
    }
    #Delete Flavor Profiles that already exist for this cloud account name. 
    #[array]$FindExistingFlavorProfile =  Get-APIData '/iaas/api/flavor-profiles' -FilterKey name -FilterValue $FindcloudAccount.name | Where-Object{$_.externalRegionId -like "us-*"} 
    [array]$FindExistingFlavorProfile =  Get-APIData '/iaas/api/flavor-profiles' -FilterKey name -FilterValue $FindcloudAccount.name -Filterkey2 "externalRegionId" -filtervalue2 "us-*"
    ForEach ($FoundFlavorProfile in $FindExistingFlavorProfile) {    
        $deleteImageProfileURL = "https://api.mgmt.cloud.vmware.com/iaas/api/flavor-profiles/"+$FoundFlavorProfile.id+ "?apiVersion="+$apiVersion
        Invoke-WebRequest -uri $deleteImageProfileURL -Method DELETE -ContentType "application/json" -UseBasicParsing -headers $headers
    }
    #Create flavor mapping for all regions using template flavor mapping
    ForEach ($newRegion in $NewCARegions) {              
            $CreateNewFlavorMapping = @{"regionId"=$newRegion.id;"name"=$FindcloudAccount.name;"flavorMapping"=$FlavorArray} | ConvertTo-Json 
            $flavorResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/flavor-profiles" -Method POST -ContentType "application/json" -headers $headers -Body $CreateNewFlavorMapping    
            if ($null -eq $flavorResults ) {$returnErrorCode += 1}
            $ResultsDetails += $CreateNewFlavorMapping
            $ResultsDetails += $flavorResults
    }
    
    #Tag all created security groups so that they can be discovered via the blueprint.    
    #Existing SG naming standard is: SG-ProjectName-Something-Something-ROLE
    # SG-DC-ALL-SERVER
    # SG-SIC2-E2-PROD-II-APP
    $securityGroups = Get-APIData -URIBit '/iaas/api/security-groups' -FilterKey cloudAccountId -FilterValue $FindcloudAccount.id -fk2 name -fv2 "SG-*"# ERROR
    ForEach ($sg in $securityGroups) {
        $nameSplit = $sg.name.split("-")
        $roleTag = $nameSplit[$nameSplit.count-1]
        $SGTag = $FindExistingProject.name + "-aws-"+$roleTag.ToLower()
        $ResourceLink = "/resources/security-groups/"+$sg.id
        $BuildSGTag = @{"resourceLink"=$ResourceLink;"tagsToAssign"=@(@{"key"="sg";"value"=$SGTag})} | ConvertTo-Json
        $SGTaggingResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/provisioning/uerp/provisioning/mgmt/tag-assignment" -Method POST -ContentType "application/json" -headers $headers -Body $BuildSGTag
        $ResultsDetails += $SGTaggingResults
    }

    ###############################################################################
    #Create basic Network profile for all regions for windows and Linux deployments. 
    $headers = AuthenticateWithVRA 
    ForEach ($thisNewRegion in $NewCARegions) {    
        #find all fabric networks defined in this new Cloud Account. TypeCast as [array] in case only one network found.
        do {
            #All Fabric networks that are associated with this cloud account, that match naming standard "sn-*"
            [array]$FabricNetworks = Get-APIData -URIBit '/iaas/api/fabric-networks' -FilterKey cloudAccountId -FilterValue $FindcloudAccount.id -fk2 "externalRegionId" -FilterValue2  $thisNewRegion.externalRegionId | Where-Object{$_.name -like "SN-*" } | Sort-Object name   
        } while ($FabricNetworks.count -eq 0 ) # -and $tries -lt 5 )     
              
        Write-verbose $thisNewRegion.externalRegionId
        $headers=AuthenticateWithVRA
        ForEach ($fn in $FabricNetworks) {
            write-verbose 'assigning new network tags'            
            $FNnameSplit = $FN.name.split("-")   #Subnet naming standard 'SN-Project-BillingCode-Environment-Role-AvailabilityZoneA/B
            $FNroleTag = $FNnameSplit[$FNnameSplit.count-2]   # Grab ROLE value from name.
            $SNURL = "/provisioning/uerp/resources/sub-networks/"+$fn.id    #Pull AZ Zone us-west-2A for this fabric network.
            $ZoneName = (Get-APIData $SNURL).zoneId
            $defaultFabricNetworkTags = @(@{"key"="network";"value"=$strNetworkTagValue})  
            $strNetworkTagValue = $FindExistingProject.name+"-aws-"+ $FNroleTag.tolower() + "-"+ $ZoneName    
            $NotFoundNetworkTag = $null -ne ($fn.tags | Where-Object{$_.key -eq "network"})                             # didn't find a network tag at all
            $FoundNetworkValue = @($fn.tags | Where-Object{$_.value -ne $strNetworkTagValue -and $_.key -eq "network"}) # found a network tag but it's for a different project    
            if ($NotFoundNetworkTag -or ($null -ne $FoundNetworkValue)) {
                $uri = "https://api.mgmt.cloud.vmware.com/provisioning/uerp/provisioning/mgmt/tag-assignment"
                $fixTags = @{"resourceLink"="/resources/sub-networks/"+$fn.id;"tagsToAssign"=$defaultFabricNetworkTags;"tagsToUnassign"=$FoundNetworkValue} | convertto-json
                Invoke-RestMethod -uri $uri -Method POST -ContentType "application/json" -UseBasicParsing -headers $headers -Body $fixTags
                $ResultsDetails += $NPResults
            }
        }
        write-verbose "building network profiles"        
        $NetworkName = $FindcloudAccount.name  
        if ($null -eq (Get-APIData -URIBit "/iaas/api/network-profiles" -filterkey name -filtervalue $NetworkName)) {
            if ($FabricNetworks.count -eq 0) {write-error $("need to manually add networks to "+$NetworkName)}   
            $fabricNetworkIDS = $FabricNetworks | ForEach-Object{$_.id}             
            $NewNetworkProfile = @{"name"=$NetworkName;"regionId"=$thisNewRegion.id;"fabricNetworkIds"=$fabricNetworkIDS;"tags"=@(@{"key"="network_profile";"value"=$($FindExistingProject.name+"_aws")})} | ConvertTo-Json -Depth 4
            write-verbose $NewNetworkProfile
            $NPResultsWindows = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/network-profiles" -Method POST -ContentType "application/json" -headers $headers -Body $NewNetworkProfile
            if ($null -eq $NPResultsWindows ) {$returnErrorCode += 1}        
            $ResultsDetails += $("Network Profile JSON:" + $NewNetworkProfile)
            $ResultsDetails += $NPResultsWindows
        }         
    }

    ################################   Create basic storage profile in AWS.  ###############################
    $headers = AuthenticateWithVRA
    ForEach ($thisNewRegion in $NewCARegions) {
        $findExistingStorageProfile = Get-APIData -URIBit "/iaas/api/storage-profiles-aws" -FilterKey externalRegionId -FilterValue $thisNewRegion.externalRegionId  | where-object{$_.name -eq $FindcloudAccount.name}
        if ($null -eq $findExistingStorageProfile) {   #make sure storage profile doesn't already exist. 
            $AllTags = @()
            $AllTags += @{"key"="storage";"value"=$($FindcloudAccount.name+":"+$thisNewRegion.externalRegionId)}
            $NewStorageProfile = @{"name"=$FindcloudAccount.name;"regionId"=$thisNewRegion.id;"deviceType"="ebs";"volumeType"="gp2";"supportsEncryption"="true";"tags"=$Alltags} | ConvertTo-Json
            $SPResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/iaas/api/storage-profiles-aws" -Method POST -ContentType "application/json" -headers $headers -Body $NewStorageProfile    
            if ($null -ne $SPResults ) {$returnErrorCode += 1}
            $ResultsDetails += $SPResults
        } else {
            Write-Verbose "Found Existing Storage Profile"
        }
    }


    ############################### Setup blueprint content sharing to new project ################
    #share the blueprint from the existing project to the new project so end-users can deploy services.
    #ref: https://api.mgmt.cloud.vmware.com/deployment/api/swagger/swagger-ui.html#/Catalog%20Entitlements/createEntitlementUsingPOST

    # Find $DevCloudAccount -> Project
    # Find Catalog Source ID tagged for that project. 
    $devHref = $findDevAccount._links.self.href
    #This is the shortest route to the Project ID that I could find. 
    # CA -> Zone -> Project 
    $DevZones = Get-APIData /iaas/api/zones | Where-Object {$_._links."cloud-account".href -eq $devHref}
    $DevProjects = $DevZones._links.Projects.hrefs | Foreach-object {Get-APIData -URIBit $_} #Get all projects that a zone is assigned.
    #Grabs ServiceBroker Content Sharing values for this/these project id.
    $CatalogEntitlement = $DevProjects | Foreach-object{Get-APIData -uribit $("/catalog/api/admin/entitlements?projectId="+$_.id )} | ForEach-Object {$_.definition.id} | Sort-Object -Unique
    if ($CatalogEntitlement -isnot [array]) {
        $EntitlementID = $CatalogEntitlement
        $BPContentSharing = @{"projectId"=$FindExistingProject.id;"definition"=@{"type"="CatalogSourceIdentifier";"id"=$EntitlementID}} | ConvertTo-Json
        $bpSharingResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/catalog/api/admin/entitlements" -Method POST -ContentType "application/json" -headers $headers -Body $BPContentSharing    
        if ($null -ne $bpSharingResults ) {$returnErrorCode += 1}
    } else { #untested code - 
            # - if a zone is added to two different projects
            # - and each  project is sharing different blueprints this should capture it.
        ForEach ($EntitlementID in $CatalogEntitlement ) {
            $BPContentSharing = @{"projectId"=$FindExistingProject.id;"definition"=@{"type"="CatalogSourceIdentifier";"id"=$EntitlementID}} | ConvertTo-Json
            $bpSharingResults = Invoke-RestMethod -uri "https://api.mgmt.cloud.vmware.com/catalog/api/admin/entitlements" -Method POST -ContentType "application/json" -headers $headers -Body $BPContentSharing    
            if ($null -ne $bpSharingResults ) {$returnErrorCode += 1}
        }
    }
  
    $ResultsDetails += $bpSharingResults
}
#If no errors found during script, then return 0 for perfect run, else dump all the results of JSON calls. 
if ($returnErrorCode -eq 0) {
    Return $ReturnErrorCode     #successful
} else {
    return $ResultsDetails      #failure
}
    }     
}


