# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

<powershell>
try {
  $url = "https://raw.githubusercontent.com/ansible/ansible/6e325d9e4dbdc020eb520a81148866d988a5dbc5/examples/scripts/ConfigureRemotingForAnsible.ps1"
  $file = "$env:temp\ConfigureRemotingForAnsible.ps1"
  (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
  powershell.exe -ExecutionPolicy ByPass -File $file
} catch {
  $_.Exception.Message
  "Error enabling WinRM on HTTPS."
}
# Check if Administrator user exists
if (-not (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue)) {
    # Create Administrator user
    Write-Output "Creating Administrator user"
    $password = ConvertTo-SecureString "ChangeMe" -AsPlainText -Force
    New-LocalUser "Administrator" -Password $password -FullName "Administrator" -Description "Administrator user for remote desktop"

    Write-Output "Adding Administrator user to RDP group."
    # Add Administrator to Remote Desktop Users group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrator"

    Write-Output "Adding Administrator user to Administrators group."
    # Add Administrator to Administrators group
    Add-LocalGroupMember -Group "Administrators" -Member "Administrator"
} else {
    Write-Output "Administrator user already exists."
    # Set the password for the Administrator account
    $admin = [ADSI]"WinNT://./Administrator, user"
    $password = "ChangeMe"
    $admin.SetPassword($password)
    $admin.SetInfo()
    Write-Output "Administrator password changed successfully."
}
</powershell>
