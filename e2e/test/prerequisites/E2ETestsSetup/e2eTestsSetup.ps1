param(
    [Parameter(Mandatory)]
    [string] $Region,

    [Parameter(Mandatory)]
    [string] $HubName,
    
    [Parameter(Mandatory)]
    [string] $SubscriptionId,

    # Follow instructions in OneNote page to generate the cer (DPS E2E configuration) and provide the path. 
    [Parameter(Mandatory)]
    [string] $PathToGroupCer,

    # This is part of the folder attached to OneNote page (DPS E2E configuration). Download and set the path correctly.
    [Parameter(Mandatory)]
    [string] $PathToGroupPfx,

    # This is part of the folder attached to OneNote page (DPS E2E configuration). Download and set the path correctly. This is the cert in -> testcertificates\indcertdevice1\certificate.cer
    [Parameter(Mandatory)]
    [string] $PathToIndividualCer,
    
    # This project is part of the repo - https://github.com/Azure-Samples/azure-iot-samples-csharp
    # Clone this repo and project will be under azure-iot-samples-csharp/provisioning/Samples/service/
    [Parameter(Mandatory)]
    [string] $PathToGroupCertificateVerificationSampleCsprojFolder,
    
    [Parameter()]
    [string] $PathToSaveConfigFile,

    # Set this to true on the first execution to get everything installed in poweshell. Does not need to be run everytime.
    [Parameter()]
    [bool] $InstallDependencies = $true,

    # Set this if you want to upload secrets to the KeyVault. Eventually we will stop writing to local disk.
    [Parameter()]
    [bool] $UploadToKeyVault = $false
)

########################################################################################################
# Set error and warning preferences for the script to run
########################################################################################################
$ErrorActionPreference = "Stop"
$WarningActionPreference = "Continue"

###########################################################################
# Connect-AzureSubscription - gets current Azure context or triggers a 
# user log in to Azure. Selects the Azure subscription for creation of 
# the virtual machine
###########################################################################
Function Connect-AzureSubscription()
{
    # Ensure the user is logged in
    try
    {
        $azureContext = az account show
    }
    catch {
    }

    if (-not $azureContext)
    {
        Write-Host "Please login to Azure..."
        az login
        $azureContext = az account show
    }

    # Ensure the desired subscription is selected
    if ($azureContext.id -ne $SubscriptionId)
    {
        Write-Host "Selecting subscription $SubscriptionId"
        az account set --subscription $SubscriptionId
    }

    return $azureContext
}

#################################################################################################
# Set required parameters
#################################################################################################

$Region = $Region.Replace(' ', '')

if (-not $StorageAccountName) {
    $StorageAccountName = "$($HubName.ToLower())sa"
}

if (-not $ResourceGroup)
{
    $ResourceGroup = $HubName
}

if(-not $AppRegistrationName)
{
    $AppRegistrationName = $ResourceGroup
}

if (-not $DeviceProvisioningServiceName)
{
    $DeviceProvisioningServiceName = $HubName
}

if (-not $FarRegion)
{
    $FarRegion = "southeastasia"
}

$FarHubName = $HubName + "Far"
$UploadCertificateName = "group1-certificate"
$SecretsKeyVaultName = "Secrets-$HubName"

########################################################################################################
#Install latest version of az cli
########################################################################################################
if($InstallDependencies  -eq $true)
{
    Install-Module -Name Az -AllowClobber -Force
    Update-Module -Name Az
}

########################################################################################################
#Install chocolatey and docker
########################################################################################################
if($InstallDependencies  -eq $true)
{
    Write-Host "Setting up docker.........."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install docker-desktop -y
    # Refresh paths after installation of choco    
    refreshenv
    docker pull aziotbld/testtpm
    docker pull aziotbld/testproxy
}

#######################################################################################################
# Install azure iot extension
#######################################################################################################
if($InstallDependencies  -eq $true)
{
    Write-Host "Installing azure iot cli extensions"
    az extension add --name azure-iot
}

######################################################################################################
# Setup azure context
######################################################################################################
$azureContext = Connect-AzureSubscription
$userObjectId = az ad signed-in-user show --query objectId --output tsv

###########################################################################
# Get-ResourceGroup - Finds or creates the resource group to be used by the
# deployment.
###########################################################################
$rgExists = az group exists --name $ResourceGroup
if ($rgExists -eq "False")
{
    $rg = az group create --name $ResourceGroup --location $Region
    Write-Host "Created resource group $ResourceGroup in $Region"
}

#######################################################################################################
# Invoke-Deployment - Uses the .\.json template to
# create the necessary resources to run E2E tests.
#######################################################################################################

# Create a unique deployment name
$randomSuffix = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
$deploymentName = "IotE2eInfra-$randomSuffix"

# Deploy
Write-Host @"
    `nStarting deployment which may take a while.
    Progress can be monitored from the Azure Portal (http://portal.azure.com).
    1. Find the resource group $ResourceGroup in subscription $SubscriptionId.
    2. In the Deployments page open deployment $deploymentName.
"@

az deployment group create  `
--resource-group $ResourceGroup `
--name $deploymentName `
--template-file '.\e2eTestsArmTemplate.json' `
--output none `
--parameters `
    Region=$Region `
    HubName=$HubName `
    StorageAccountName=$StorageAccountName `
    DeviceProvisioningServiceName=$DeviceProvisioningServiceName `
    FarHubName=$FarHubName `
    FarRegion=$FarRegion `
    UserObjectId=$userObjectId

Write-Host "Your infrastructure is ready in subscription ($SubscriptionId), resource group ($ResourceGroup)"

#########################################################################################################
# Get propreties to setup the config file for Environment variables
# TODO: Get the secrets from a KV
#########################################################################################################
Write-Host "Getting secrets from ARM template output"
$iotHubThumbprint = "CADB8E398FA9C7DD382E2ED092258BB3D916652C"
$iotHubConnectionString = az deployment group show -g $ResourceGroup -n $deploymentName --query 'properties.outputs.hubConnectionString.value' --output tsv
$eventHubConnectionString = az deployment group show -g $ResourceGroup -n $deploymentName  --query 'properties.outputs.eventHubConnectionString.value' --output tsv
$storageAccountConnectionString = az deployment group show -g $ResourceGroup -n $deploymentName  --query 'properties.outputs.storageAccountConnectionString.value' --output tsv
$deviceProvisioningServiceConnectionString = az deployment group show -g $ResourceGroup -n $deploymentName  --query 'properties.outputs.deviceProvisioningServiceConnectionString.value' --output tsv
$eventHubName = az resource show -g $ResourceGroup --resource-type microsoft.devices/iothubs -n $HubName --query 'properties.eventHubEndpoints.events.path' --output tsv
$workspaceId = az deployment group show -g $ResourceGroup -n $deploymentName --query 'properties.outputs.workspaceId.value' --output tsv
$consumerGroups = "e2e-tests"
$proxyServerAddress = "127.0.0.1:8888"

##################################################################################################################################
# Uploading certificate to DPS, verifying and creating enrollment groups
##################################################################################################################################
$dpsIdScope = az iot dps show -g $ResourceGroup --name $DeviceProvisioningServiceName --query 'properties.idScope' --output tsv
$certExits = az iot dps certificate list -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --query "value[?name=='$UploadCertificateName']" --output tsv
if($certExits -eq $null)
{
    Write-Host "Uploading certificate to DPS"
    $dpsCert = az iot dps certificate create -g $ResourceGroup --path $PathToGroupCer --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName
}
$isVerified = az iot dps certificate show -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName --query 'properties.isVerified' --output tsv
if($isVerified -eq 'false')
{
    Write-Host "Verifying certificate uploaded to DPS"
    $etag = az iot dps certificate show -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName --query 'etag'
    $verificationCode = az iot dps certificate generate-verification-code -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName -e $etag --query 'properties.verificationCode'
    $verificationCert = dotnet run --project $PathToGroupCertificateVerificationSampleCsprojFolder $PathToGroupPfx testcertificate $verificationCode
    $currentDir = Get-Location
    $PathToVerificationCertificateCer = Join-Path -Path $currentDir -ChildPath "verificationCertificate.cer"
    $etag = az iot dps certificate show -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName --query 'etag'
    az iot dps certificate verify -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --certificate-name $UploadCertificateName -e $etag --path $PathToVerificationCertificateCer --output none
}

$GroupEnrollmentId = "Group1"
$groupEnrollmentExists = az iot dps enrollment-group list -g $ResourceGroup  --dps-name $DeviceProvisioningServiceName --query "[?enrollmentGroupId=='$GroupEnrollmentId'].enrollmentGroupId" --output tsv
if($groupEnrollmentExists -eq $null)
{
    Write-Host "Adding group enrollment $GroupEnrollmentId"
    az iot dps enrollment-group create -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --enrollment-id $GroupEnrollmentId --ca-name $UploadCertificateName --output none
}

$IndividualEnrollmentId = "iothubx509device1"
$individualDeviceId = "provisionedx509device1"
$individualEnrollmentExists = az iot dps enrollment list -g $ResourceGroup  --dps-name $DeviceProvisioningServiceName --query "[?deviceId=='$individualDeviceId'].deviceId" --output tsv
if($groupEnrollmentExists -eq $null)
{
    Write-Host "Adding individual enrollment $IndividualEnrollmentId for device $individualDeviceId"
    az iot dps enrollment create -g $ResourceGroup --dps-name $DeviceProvisioningServiceName --enrollment-id $IndividualEnrollmentId --device-id $individualDeviceId --attestation-type x509 --certificate-path $PathToIndividualCer --output none
}

#################################################################################################################################################
# Configure an AAD app and create self signed certs and get the bytes to generate more content info.
#################################################################################################################################################
$appId = az ad app list --show-mine --query "[?displayName=='$AppRegistrationName'].appId" --output tsv
if($appId -eq $null)
{
    Write-Host "Creating App Registration $AppRegistrationName"
    $appId = az ad app create --display-name $AppRegistrationName --reply-urls https://api.loganalytics.io/ --available-to-other-tenants false --query 'appId' --output tsv --output none
    Write-Host "Application $AppRegistrationName with Id $appId was created successfully."
}
$appId = az ad app list --show-mine --query "[?displayName=='$AppRegistrationName'].appId" --output tsv

$spExists = az ad sp list --show-mine --query "[?appId=='$appId'].appId" --output tsv
if($spExists -eq $null)
{
    Write-Host "Creating the service principal for the app registration if it does not exist"
    az ad sp create --id $appId --output none
}

# The Service Principal takes a while to get propogated and if a different endpoint is hit before that, trying to grant a permission will fail.
# Adding retries so that we can grant the permissions successfully without re-running the script.
$retry = $true
$retryCount = 1;
while($retry -eq $true)
{
    try
    {
        Write-Host "Granting $appId Reader role assignment to the $Resourcegroup resource group - Trial $retryCount"
        az role assignment create --role Reader --assignee $appId --resource-group $ResourceGroup --output none
        $retry = $false
    }
    catch
    {
        $retryCount++
        if($retryCount -eq 10)
        {
            Write-Host "Max retries reached"
            $retry = $false
        }
    }
}

Write-Host "Creating a self signed certificate and placing it in $HubName"
az ad app credential reset --id $appId --create-cert --keyvault $HubName --cert $HubName --output none
Write-Host "Successfully created a self signed cert for your application $AppRegistrationName in $HubName Keyvault: Cert name : $HubName";

Write-Host "Fetching the certificate binary"
if(Test-Path ".\selfSignedCerts" -PathType Leaf){
    Remove-Item -r .\selfSignedCert 
}

az keyvault secret download --file .\selfSignedCert --vault-name $HubName -n $HubName --encoding base64
$fileContent = Get-Content .\selfSignedCert -Encoding Byte
$fileContentB64String = [System.Convert]::ToBase64String($fileContent);

Write-Host "Successfully fetched the certificate bytes ... removing the cert file from the disk"
Remove-Item -r .\selfSignedCert

$IOTHUB_X509_PFX_CERTIFICATE = ""
$DPS_INDIVIDUALX509_PFX_CERTIFICATE = ""
$DPS_GROUPX509_PFX_CERTIFICATE = ""
$DPS_GROUPX509_CERTIFICATE_CHAIN = ""
$DPS_X509_PFX_CERTIFICATE_PASSWORD = ""

#################################################################################################################################################
# Generate a Config file with all the Environment vairables that need to be added before running the tests
#################################################################################################################################################

# Generate config file for command prompt

$currentDir = Get-Location
Write-Host "Output in '$currentDir\iotConfig.cmd'"
$file = New-Item  -Path $currentDir -Name "iotConfig.cmd" -ItemType "file" -Force
Add-Content -Path $file.PSPath -Value "set IOTHUB_CONN_STRING_CSHARP=$iotHubConnectionString"
Add-Content -Path $file.PSPath -Value "set IOTHUB_PFX_X509_THUMBPRINT=$iotHubThumbprint"
Add-Content -Path $file.PSPath -Value "set IOTHUB_EVENTHUB_CONN_STRING_CSHARP=$eventHubConnectionString"
Add-Content -Path $file.PSPath -Value "set IOTHUB_EVENTHUB_COMPATIBLE_NAME=$eventHubName"
Add-Content -Path $file.PSPath -Value "set IOTHUB_EVENTHUB_CONSUMER_GROUP=$consumerGroups"
Add-Content -Path $file.PSPath -Value "set IOTHUB_PROXY_SERVER_ADDRESS=$proxyServerAddress"
Add-Content -Path $file.PSPath -Value "set FAR_AWAY_IOTHUB_HOSTNAME=$FarHubName.azure-devices.net"
Add-Content -Path $file.PSPath -Value "set DPS_IDSCOPE=$dpsIdScope"
Add-Content -Path $file.PSPath -Value "set PROVISIONING_CONNECTION_STRING=$deviceProvisioningServiceConnectionString"
Add-Content -Path $file.PSPath -Value "set CUSTOM_ALLOCATION_POLICY_WEBHOOK=https://drwe2efnapp.azurewebsites.net/api/HttpTrigger1?code=PtayXB9/P7E5Wt0AmmSs5oO1n0n3jNEM3zDkq3U8VQSziNSMCINOGw=="
Add-Content -Path $file.PSPath -Value "set DPS_GLOBALDEVICEENDPOINT=global.azure-devices-provisioning.net"
Add-Content -Path $file.PSPath -Value "set DPS_X509_PFX_CERTIFICATE_PASSWORD=$DPS_X509_PFX_CERTIFICATE_PASSWORD"
Add-Content -Path $file.PSPath -Value "set IOTHUB_X509_PFX_CERTIFICATE=$IOTHUB_X509_PFX_CERTIFICATE"
Add-Content -Path $file.PSPath -Value "set DPS_INDIVIDUALX509_PFX_CERTIFICATE=$DPS_INDIVIDUALX509_PFX_CERTIFICATE"
Add-Content -Path $file.PSPath -Value "set DPS_GROUPX509_PFX_CERTIFICATE=$DPS_GROUPX509_PFX_CERTIFICATE"
Add-Content -Path $file.PSPath -Value "set DPS_GROUPX509_CERTIFICATE_CHAIN=$DPS_GROUPX509_CERTIFICATE_CHAIN"
Add-Content -Path $file.PSPath -Value "set IOTHUB_DEVICE_CONN_STRING_INVALIDCERT=HostName=invalidcertiothub1.westus.cloudapp.azure.com;DeviceId=DoNotDelete1;SharedAccessKey=zWmeTGWmjcgDG1dpuSCVjc5ZY4TqVnKso5+g1wt/K3E="
Add-Content -Path $file.PSPath -Value "set IOTHUB_CONN_STRING_INVALIDCERT=HostName=invalidcertiothub1.westus.cloudapp.azure.com;SharedAccessKeyName=iothubowner;SharedAccessKey=Fk1H0asPeeAwlRkUMTybJasksTYTd13cgI7SsteB05U="
Add-Content -Path $file.PSPath -Value "set DPS_GLOBALDEVICEENDPOINT_INVALIDCERT=invalidcertgde1.westus.cloudapp.azure.com"
Add-Content -Path $file.PSPath -Value "set PROVISIONING_CONNECTION_STRING_INVALIDCERT=HostName=invalidcertdps1.westus.cloudapp.azure.com;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=lGO7OlXNhXlFyYV1rh9F/lUCQC1Owuh5f/1P0I1AFSY="
Add-Content -Path $file.PSPath -Value "set STORAGE_ACCOUNT_CONNECTION_STRING=$storageAccountConnectionString"
Add-Content -Path $file.PSPath -Value "set LA_WORKSPACE_ID=$workspaceId"
Add-Content -Path $file.PSPath -Value "set LA_AAD_TENANT=72f988bf-86f1-41af-91ab-2d7cd011db47"
Add-Content -Path $file.PSPath -Value "set LA_AAD_APP_ID=$appId"
Add-Content -Path $file.PSPath -Value "set LA_AAD_APP_CERT_BASE64=$fileContentB64String"

# Generate config file for powershell

Write-Host "Output in '$currentDir\iotPowershellConfig.ps1'"
$file = New-Item  -Path $currentDir -Name "iotPowershellConfig.ps1" -ItemType "file" -Force
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_CONN_STRING_CSHARP=`"$iotHubConnectionString`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_PFX_X509_THUMBPRINT=`"$iotHubThumbprint`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_EVENTHUB_CONN_STRING_CSHARP=`"$eventHubConnectionString`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_EVENTHUB_COMPATIBLE_NAME=`"$eventHubName`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_EVENTHUB_CONSUMER_GROUP=`"$consumerGroups`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_PROXY_SERVER_ADDRESS=`"$proxyServerAddress`""
Add-Content -Path $file.PSPath -Value "`$env:FAR_AWAY_IOTHUB_HOSTNAME=`"$FarHubName.azure-devices.net`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_IDSCOPE=`"$dpsIdScope`""
Add-Content -Path $file.PSPath -Value "`$env:PROVISIONING_CONNECTION_STRING=`"$deviceProvisioningServiceConnectionString`""
Add-Content -Path $file.PSPath -Value "`$env:CUSTOM_ALLOCATION_POLICY_WEBHOOK=`"https://drwe2efnapp.azurewebsites.net/api/HttpTrigger1?code=PtayXB9/P7E5Wt0AmmSs5oO1n0n3jNEM3zDkq3U8VQSziNSMCINOGw==`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_GLOBALDEVICEENDPOINT=`"global.azure-devices-provisioning.net`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_X509_PFX_CERTIFICATE_PASSWORD=`"$DPS_X509_PFX_CERTIFICATE_PASSWORD`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_X509_PFX_CERTIFICATE=`"IOTHUB_X509_PFX_CERTIFICATE`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_INDIVIDUALX509_PFX_CERTIFICATE=`"$DPS_INDIVIDUALX509_PFX_CERTIFICATE`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_GROUPX509_PFX_CERTIFICATE=`"$DPS_GROUPX509_PFX_CERTIFICATE`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_GROUPX509_CERTIFICATE_CHAIN=`"$DPS_GROUPX509_CERTIFICATE_CHAIN`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_DEVICE_CONN_STRING_INVALIDCERT=`"HostName=invalidcertiothub1.westus.cloudapp.azure.com;DeviceId=DoNotDelete1;SharedAccessKey=zWmeTGWmjcgDG1dpuSCVjc5ZY4TqVnKso5+g1wt/K3E=`""
Add-Content -Path $file.PSPath -Value "`$env:IOTHUB_CONN_STRING_INVALIDCERT=`"HostName=invalidcertiothub1.westus.cloudapp.azure.com;SharedAccessKeyName=iothubowner;SharedAccessKey=Fk1H0asPeeAwlRkUMTybJasksTYTd13cgI7SsteB05U=`""
Add-Content -Path $file.PSPath -Value "`$env:DPS_GLOBALDEVICEENDPOINT_INVALIDCERT=`"invalidcertgde1.westus.cloudapp.azure.com`""
Add-Content -Path $file.PSPath -Value "`$env:PROVISIONING_CONNECTION_STRING_INVALIDCERT=`"HostName=invalidcertdps1.westus.cloudapp.azure.com;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=lGO7OlXNhXlFyYV1rh9F/lUCQC1Owuh5f/1P0I1AFSY=`""
Add-Content -Path $file.PSPath -Value "`$env:STORAGE_ACCOUNT_CONNECTION_STRING=`"$storageAccountConnectionString`""
Add-Content -Path $file.PSPath -Value "`$env:LA_WORKSPACE_ID=`"$workspaceId`""
Add-Content -Path $file.PSPath -Value "`$env:LA_AAD_TENANT=`"72f988bf-86f1-41af-91ab-2d7cd011db47`""
Add-Content -Path $file.PSPath -Value "`$env:LA_AAD_APP_ID=`"$appId`""
Add-Content -Path $file.PSPath -Value "`$env:LA_AAD_APP_CERT_BASE64=`"$fileContentB64String`""

###################################################################################################################################
# Store all secrets in a KeyVault - This will be used by our pipeline. 
# TODO: Use this locally as well instead of saving a config file
###################################################################################################################################
if($UploadToKeyVault -eq $true)
{
    # Ensure length of the KV name does not exceed 24 characters
    if($SecretsKeyVaultName.Length > 24)
    {
        $SecretsKeyVaultName = $SecretsKeyVaultName.Substring(0, 24)
    }
    Write-Host "Uploading secrets to KeyVault $SecretsKeyVaultName"
    az keyvault create -g $ResourceGroup --name $SecretsKeyVaultName --output none
    az keyvault set-policy -g $ResourceGroup --name $SecretsKeyVaultName --object-id $userObjectId --secret-permissions delete get list set --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-CONN-STRING-CSHARP" --value $iotHubConnectionString --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-PFX-X509-THUMBPRINT" --value $iotHubThumbprint --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-EVENTHUB-CONN-STRING-CSHARP" --value $iotHubConnectionString --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-EVENTHUB-COMPATIBLE-NAME" --value $eventHubName --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-EVENTHUB-CONSUMER-GROUP" --value $consumerGroups --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-PROXY-SERVER-ADDRESS" --value $proxyServerAddress --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "FAR-AWAY-IOTHUB-HOSTNAME" --value "$FarHubName.azure-devices.net" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-IDSCOPE" --value $dpsIdScope --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "PROVISIONING-CONNECTION-STRING" --value $deviceProvisioningServiceConnectionString --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "CUSTOM-ALLOCATION-POLICY-WEBHOOK" --value "https://drwe2efnapp.azurewebsites.net/api/HttpTrigger1?code=PtayXB9/P7E5Wt0AmmSs5oO1n0n3jNEM3zDkq3U8VQSziNSMCINOGw==" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-GLOBALDEVICEENDPOINT" --value "global.azure-devices-provisioning.net" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-X509-PFX-CERTIFICATE-PASSWORD" --value $DPS_X509_PFX_CERTIFICATE_PASSWORD --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-X509-PFX-CERTIFICATE" --value $IOTHUB_X509_PFX_CERTIFICATE --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-INDIVIDUALX509-PFX-CERTIFICATE" --value $DPS_INDIVIDUALX509_PFX_CERTIFICATE --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-GROUPX509-PFX-CERTIFICATE" --value $DPS_GROUPX509_PFX_CERTIFICATE --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "DPS-GROUPX509-CERTIFICATE-CHAIN" --value $DPS_GROUPX509_CERTIFICATE_CHAIN --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-DEVICE-CONN-STRING-INVALIDCERT" --value "HostName=invalidcertiothub1.westus.cloudapp.azure.com;DeviceId=DoNotDelete1;SharedAccessKey=zWmeTGWmjcgDG1dpuSCVjc5ZY4TqVnKso5+g1wt/K3E=" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "IOTHUB-CONN-STRING-INVALIDCERT" --value "HostName=invalidcertiothub1.westus.cloudapp.azure.com;SharedAccessKeyName=iothubowner;SharedAccessKey=Fk1H0asPeeAwlRkUMTybJasksTYTd13cgI7SsteB05U=" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "PROVISIONING-CONNECTION-STRING-INVALIDCERT" --value "HostName=invalidcertdps1.westus.cloudapp.azure.com;SharedAccessKeyName=provisioningserviceowner;SharedAccessKey=lGO7OlXNhXlFyYV1rh9F/lUCQC1Owuh5f/1P0I1AFSY=" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "STORAGE-ACCOUNT-CONNECTION-STRING" --value $storageAccountConnectionString --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "LA-WORKSPACE-ID" --value $workspaceId --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "LA-AAD-TENANT" --value "72f988bf-86f1-41af-91ab-2d7cd011db47" --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "LA-AAD-APP-ID" --value $appId --output none
    az keyvault secret set --vault-name $SecretsKeyVaultName --name "LA-AAD-APP-CERT-BASE64" --value $fileContentB64String --output none
}


###################################################################################################################################
#Run docker containers for TPM simulators and Proxy
###################################################################################################################################

if(-not (docker images -q aziotbld/testtpm))
{
    Write-Host "Setting up docker container for TPM simulator"
    docker run -d --restart unless-stopped --name azure-iot-tpmsim -p 127.0.0.1:2321:2321 -p 127.0.0.1:2322:2322 aziotbld/testtpm
}

if(-not (docker images -q aziotbld/testproxy))
{
    Write-Host "Setting up docker container for Proxy"
    docker run -d --restart unless-stopped --name azure-iot-tinyproxy -p 127.0.0.1:8888:8888 aziotbld/testproxy
}

###################################################################################################################################