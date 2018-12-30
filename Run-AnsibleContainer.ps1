# Necessary params, to be passed on CMD line
param (
        [Parameter(Position=0)][string]$ucpFQDN,
        [Parameter()][string]$ucpAdmin,
        [Parameter()][string]$ucpPW,
        [Parameter()][string]$AnsibleImage,
        [Parameter()][string]$WindowsTarget,
        [Parameter()][string]$AnsibleUser,
        [Parameter()][string]$AnsiblePassword
    )

# Necessary block to ignore Cert errors, during this session only
# equivalent to 'Curl -K'
# for what ever reason, the @" "@ operator doesn't allow whitespace ahead of the multiline string...
function Set-CertPolicy{
param()
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Run-AnsibleContainer{
    param (
        [Parameter(Position=0,Mandatory=$true)][string]$ucpFQDN,
        [Parameter(Mandatory=$true)][string]$ucpAdmin,
        [Parameter(Mandatory=$true)][string]$ucpPW,
        [Parameter(Mandatory=$true)][string]$AnsibleImage,
        [Parameter(Mandatory=$true)][string]$WindowsTarget,
        [Parameter(Mandatory=$true)][string]$AnsibleUser,
        [Parameter(Mandatory=$true)][string]$AnsiblePassword
    )
    $UCPurl = "https://" + $ucpFQDN 
    
    # Get Auth Token
    $authEndpoint = "/auth/login"
    $authURI = $UCPurl + $authEndpoint
    $authBody = @{ "username" = $ucpAdmin ; "password" = $ucpPW } | ConvertTo-Json
    $authtoken = Invoke-RestMethod -Uri $authURI -Body $authBody -Method Post
    $authtoken = $authtoken.auth_token
    
    # Try to Run Container docker_ansible_test2:latest
    $header = @{"Authorization" = "Bearer " + $authtoken}
    
    # Build API payload for CREATE
    $endpoint = "/containers/create"
    $URI = $UCPurl + $endpoint
    $body = @{ 
        "AttachStdin" = $false
        "AttachStdout" = $true
        "AttachStderr" = $true
        "Image" = $ansibleImage  
        "ENV" = @(
            "WINDOWS_TARGET=$WindowsTarget",
            "ANSIBLEUSER=$AnsibleUser",
            "ANSIBLEPASSWORD=$AnsiblePassword"
        )
        "EntryPoint" = "/bin/bash"
        "Cmd" = "/tmp/windows-ansible/windows-ansible-playbook/wrapper.sh"
        "HostConfig" = @{ 
            "AutoRemove" = $true,
            "LogConfig" = @{ "Type" = "json-file"}
        }
    } | ConvertTo-Json
    
    # Create the container
    $CreateResponse = Invoke-RestMethod -Uri $URI -Headers $header -Method Post -ContentType "application/json" -Body $body

    # Build API Payload for START
    $containerID = $CreateResponse.ID
    $endpoint = "/containers/$containerID/start"
    $URI = $UCPurl + $endpoint

    # Start the container that we created
    $StartResponse = Invoke-RestMethod -Uri $URI -Headers $header -Method Post -ContentType "application/json"
    echo $StartResponse
}

# Ignore-Certs
Set-CertPolicy

Start-Sleep -s 5

if (!$WindowsTarget) {
    $WindowsTarget = Invoke-RestMethod http://169.254.169.254/latest/meta-data/local-ipv4
}


Run-AnsibleContainer -ucpFQDN $ucpFQDN -ucpAdmin $ucpAdmin -ucpPW $ucpPW -AnsibleImage $AnsibleImage -WindowsTarget $WindowsTarget -AnsibleUser $AnsibleUser -AnsiblePassword $AnsiblePassword
