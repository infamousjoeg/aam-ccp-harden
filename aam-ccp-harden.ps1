#######################
# Assumptions Made:
# #
# # Script executed by human user
# # Script executed on CCP Host

#######################
# Permissions Needed:
# # 
# # The “Manage Users” permission is required to be held by the user running the function.

# Check for psPAS module and install if missing
if (!$(Get-InstalledModule psPAS -ErrorAction SilentlyContinue)) {
    Install-Module psPAS -Confirm:$False -Force
}

# Import psPAS module
Import-Module psPAS

# Function for colorized Write-Output
function Color ($fc) {
    process { Write-Host $_ -ForegroundColor $fc }
}

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
    BaseURI = $pasBaseURI.Trim().ToLower()
}

# Switch case depending on authentication method chosen
Switch ($pasAuthType) {
    1{
        # Add AuthType and logon to PAS REST API
        $pasAuth.Add("Type", "cyberark")
        try {
            New-PASSession @pasAuth -Credential $(Get-Credential)
            Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" | Color Green
        } catch {
            Write-Output "==> [FAILED] could not log onto CyberArk PAS REST API" | Color Red
            exit 1
        }
    }
    2{
        # Add AuthType and logon to PAS REST API
        $pasAuth.Add("Type", "ldap")
        try {
            New-PASSession @pasAuth -Credential $(Get-Credential)
            Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" | Color Green
        } catch {
            Write-Output "==> [FAILED] could not log onto CyberArk PAS REST API" | Color Red
            exit 1
        }
    }
    3{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("Type", "radius")
        $pasAuth.Add("OTPMode", "challenge")
        try {
            New-PASSession @pasAuth -Credential $(Get-Credential) -OTP $(Read-Host "Enter your one-time passcode")
            Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" | Color Green
        } catch {
            Write-Output "==> [FAILED] could not log onto CyberArk PAS REST API" | Color Red
            exit 1
        }
    }
    4{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("Type", "radius")
        try {
            New-PASSession @pasAuth -Credential $(Get-Credential)
            Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" | Color Green
        } catch {
            Write-Output "==> [FAILED] could not log onto CyberArk PAS REST API" | Color Red
            exit 1
        }
    }
    5{
        # Add AuthType, OTPMode and logon to PAS REST API
        $pasAuth.Add("Type", "radius")
        $pasAuth.Add("OTPMode", "append")
        try {
            New-PASSession @pasAuth -Credential $(Get-Credential)
            Write-Output "==> [SUCCESS] logged onto CyberArk PAS REST API" | Color Green
        } catch {
            Write-Output "==> [FAILED] could not log onto CyberArk PAS REST API" | Color Red
            exit 1
        }
    }
}

# If AIMWebService App ID is NOT found...
if (!$(Get-PASApplication -AppID AIMWebService)) {
    Write-Output "==> [CREATE] did not detect AIMWebService App ID" | Color Green
    # ... add AIMWebService into the Applications module
    try {
        Add-PASApplication -AppID AIMWebService -Description "AAM CCP Web Service App ID" -Location "\"
        Write-Output "==> [SUCCESS] created Application ID: AIMWebService" | Color Green
    } catch {
        Write-Output "==> [FAILED] could not create AIMWebService App ID" | Color Red
        exit 1
    }
    # If AIMWebService App ID IS found...
} else {
    Write-Output "==> [SKIPPED] detected AIMWebService App ID" | Color Yellow
}

# Begin adding authentication methods to AIMWebService App ID...

# # Add Path Authentication
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -path "C:\inetpub\wwwroot\AIMWebService\bin\AIMWebService.dll" -ErrorAction SilentlyContinue
Write-Output "==> [SUCCESS] Added Path Authentication" | Color Green

# # Add OSUser Authentication
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -osUser "IISAPPPOOL\DefaultAppPool"
Write-Output "==> [SUCCESS] Added OSUser Authentication" | Color Green

# # Add Hash Authentication
# # # Use NETAIMGetAppInfo.exe to generate hash of AIMWebService.dll
$getHashResponse = $(& "C:\Program Files (x86)\CyberArk\ApplicationPasswordProvider\Utils\NETAIMGetAppInfo.exe" GetHash /AppExecutablesPattern="C:\inetpub\wwwroot\AIMWebService\bin\AIMWebService.dll")
# # # Response returns success message and hash value - need to split at line break
$aamHashValue = $getHashResponse.Split("`r`n")
# # # Reference first value in array created from split
Add-PASApplicationAuthenticationMethod -AppID AIMWebService -hash $aamHashValue[0] -ErrorAction SilentlyContinue
Write-Output "==> [SUCCESS] Added Hash Authentication" | Color Green

# # Add Machine Address Authentication
# # # Find local host's IP address from Get-NetIPAddress
$aamMachineIP = (Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4).IPAddress

# # # Loop thru returned addresses and omit loopback
foreach( $ip in $aamMachineIP){
    if ("127.0.0.1" -ne $ip) {
        # # # Add IP address
        Add-PASApplicationAuthenticationMethod -AppID AIMWebService -machineAddress $ip -ErrorAction SilentlyContinue
        Write-Output "==> [SUCCESS] Added $ip to Machine Address Authentication" | Color Green
    }
}

Write-Output "`r`n`r`n*** Completed AIMWebService hardening successfully. ***" | Color Cyan
