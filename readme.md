# vra-New-Account.ps1
## description
Configure a new AWS account in VRA so that can use existing blueprints. 
## introduction
vmWare Realize Automation - Cloud Assembly (vra-cas) can be configured to deploy and manage (day-2) servers deployed in AWS. In order to effectively deploy servers using blueprints in VRA Service Broker requires configuration of approximately 20 different items. This project is automate that configuration and standarize configuration settings. <br>

_What it configures:_ <br>
1. AWS Cloud Account created
    1. Cloud zone confirmed
    2. Cloud zones tagged
        1. cz:accountname-aws-czRegion
2. VRA Project created
    1. availibity zones tagged
        1. az:$FindcloudAccount.name +"-aws-"+ $FoundAZ.name
    2. subnets tagged and added to profile
    3. default  admins added to project
    4. cloud zones added to project (for provisioning)  
4. image profiles updated to include new cloud zone(s)
    1. copies image profiles of a 'master' account
    2. duplicates are deleted.
5. flavor profiles updated to include new cloud zone(s)    
    1. copies image profiles of a 'master' account
    2. duplicates are deleted
6. security groups are tagged
    1. sg:$FindExistingProject.name + "-aws-"+$roleTag.ToLower() 
    2. roleTag is pulled from existing security group name 
7. Network profile created for each zone
    1. fabric networks identified and tagged
        1. network:$FindExistingProject.name+"-aws-"+ $FNroleTag.tolower() + "-"+ $ZoneName 
        2. FindExistingProject is the project object found after the project is created.
        3. FNRoleTag is pulled directly from the fabric network based off the naming standard
        4. zoneName is the aws region name (ie us-west-2a)
    2. network profile tagged
        1. network-name:FindExistingProject.name+"-aws"
8. Storage profile created for each zone
    1. basic storage policy defined
    2. storage tagged
        1. storage:$FindcloudAccount.name+":"+$thisNewRegion.externalRegionId
9. share blueprint repository from master 


## dependencies
* AWS account created and network resources configured using default naming standard.
* power user account 
* Powershell v3 or greater
* VRA Cloud Assembly Admin account 
## usage
```powershell
.\vra-new-account.ps1 -strAccountName "MyNewAWSEnvironment" -strCloudAccountAccessKey "abc123akjhsd" -strCloudAccountSecretKey "longpassword-to-be-entered-here"
```

## parameters
|name|purpose|
|---|----|
|strAccountName| Account name is populated throughout VRA. Needs to be unique as to not overlap other existing cloud accounts in VRA. This will become the Cloud Account name, project name, network profile names, and storage profile name. Value must not contain spaces, the script will remove them and change the value if present. | 
|strCloudAccountAccessKey | The access key is from an account that has been granted programatic access and "POWER USER" role to the new AWS account. |
|strCloudAccountSecretKey | 'password' for the new AWS service account.|

 
## contributing
This project is held in GitHub and follows standard feature branch workflow. If you wish to contribute to the development of this project, please reach out to the authors listed in the Authors section. You can always clone the project, make changes, and complete a pull request. However, without prior notice to the authors, pull requests will be rejected.<br>
