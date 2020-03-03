Import-Module psPAS

#######################
# Assumptions Made:
# #
# # Script executed by human user
# # Script executed on CCP Host

#######################
# Permissions Needed:
# # 
# # The “Manage Users” permission is required to be held by the user running the function.

# Ask for base PVWA address
do {
    $pasBaseURI = Read-Host "Enter base PVWA address (eg. https://pvwa.example.com)"
} until ($pasBaseURI.StartsWith("https://") -or $pasBaseURI.StartsWith("http://"))

# Ask for authentication method
Write-Output "Enter authentication method for logon:"
do {
    $pasAuthType = Read-Host "[1] CyberArk [2] LDAP [3] Radius Challenge [4] Radius Push [5] Radius Append"
} until ($pasAuthType -ge 1 -and $pasAuthType -le 5)

# Create hash table for New-PASSession parameters
$pasAuth = @{
    BaseURI     = $pasBaseURI.Trim().ToLower()
}

# Switch case depending on authentication method chosen
Switch ($pasAuthType) {
    1{
        # Add AuthType and logon to PAS REST API
        $pasAuth.Add("AuthType", "cyberark")
        New-PASSession @pasAuth -Credential $(Get-Credential) -ErrorAction Stop
        Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" -ForegroundColor Green
    }
    2{
        # Add AuthType and logon to PAS REST API
        $pasAuth.Add("AuthType", "ldap")
        New-PASSession @pasAuth -Credential $(Get-Credential) -ErrorAction Stop
        Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" -ForegroundColor Green
    }
    3{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("AuthType", "radius")
        $pasAuth.Add("OTPMode", "challenge")
        New-PASSession @pasAuth -Credential $(Get-Credential) -OTP $(Read-Host "Enter your one-time passcode") -ErrorAction Stop
        Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" -ForegroundColor Green
    }
    4{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("AuthType", "radius")
        $pasAuth.Add("OTPMode", "push")
        New-PASSession @pasAuth -Credential $(Get-Credential) -ErrorAction Stop
        Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" -ForegroundColor Green
    }
    5{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("AuthType", "radius")
        $pasAuth.Add("OTPMode", "append")
        New-PASSession @pasAuth -Credential $(Get-Credential) -ErrorAction Stop
        Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" -ForegroundColor Green
    }
}

# If AIMWebService App ID is NOT found...
if (!$(Get-PASApplication -AppID AIMWebService)) {
    Write-Output "==> [CREATE] Did not detect AIMWebService App ID" -ForegroundColor Green
    # ... add AIMWebService into the Applications module
    Add-PASApplication -AppID AIMWebService -Description "AAM CCP Web Service App ID" -Location "\" -ErrorAction Stop
    Write-Output "==> [SUCCESS] Created Application ID: AIMWebService" -ForegroundColor Green
# If AIMWebService App ID IS found...
} else {
    Write-Output "==> [SKIPPED] Detected AIMWebService App ID" -ForegroundColor Yellow
}

# Begin adding authentication methods to AIMWebService App ID...
# # Add Path Authentication
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -AuthType path -AuthValue "C:\inetpub\wwwroot\AIMWebService\bin\AIMWebService.dll" -ErrorAction SilentlyContinue
Write-Output "==> [SUCCESS] Added Path Authentication" -ForegroundColor Green
# # Add OSUser Authentication
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -AuthType osuser -AuthValue "IISAPPPOOL\DefaultAppPool"
Write-Output "==> [SUCCESS] Added OSUser Authentication" -ForegroundColor Green
# # Add Hash Authentication
# # # Use NETAIMGetAppInfo.exe to generate hash of AIMWebService.dll
$getHashResponse = $(& "C:\Program Files (x86)\CyberArk\ApplicationPasswordProvider\Utils\NETAIMGetAppInfo.exe" GetHash /AppExecutablePatterns="C:\inetpub\wwwroot\AIMWebService\bin\AIMWebService.dll")
# # # Response returns success message and hash value - need to split at line break
$aamHashValue = $getHashResponse.Split("`r`n")
# # # Reference first value in array created from split
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -AuthType hash -AuthValue $aamHashValue[0] -ErrorAction SilentlyContinue
Write-Output "==> [SUCCESS] Added Hash Authentication" -ForegroundColor Green
# # Add Machine Address Authentication
# # # Find local host's IP address from ipconfig
$aamMachineAddress = ipconfig | findstr /i IPv4 | Out-String
# # # Trim off starting and ending notation
$aamMachineAddress = $aamMachineAddress.TrimStart("IPv4 Address. . . . . . . . . . . : ")
$aamMachineAddress = $aamMachineAddress.TrimEnd("`r`n")
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -AuthType machineAddress -AuthValue $aamMachineAddress -ErrorAction SilentlyContinue
Write-Output "==> [SUCCESS] Added Machine Address Authentication" -ForegroundColor Green
Write-Output "`r`n`r`n*** Completed AIMWebService hardening successfully. ***" -ForegroundColor Cyan