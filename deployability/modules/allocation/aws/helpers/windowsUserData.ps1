# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

<powershell>
try {
  Write-Output "Executing winrm quickconfig"
  if (-not ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12)) {
    Write-Output "Enabling TLS 1.2"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  }
  # Check if WinRM HTTPS listener is configured
  $httpsListener = Get-Item -Path WSMan:\LocalHost\Listener\* | Where-Object { $_.Keys -contains 'Transport' -and $_.Transport -eq 'HTTPS' }

  if ($httpsListener) {
      # Remove existing HTTPS listener
      Write-Output "Removing existing HTTPS listener."
      Remove-Item -Path WSMan:\LocalHost\Listener\$($httpsListener.Name) -Force
  }
  # Create a self-signed certificate
  $cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName $env:COMPUTERNAME

  # Enable PSRemoting and set up HTTPS listener
  Enable-PSRemoting -SkipNetworkProfileCheck -Force
  New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force

  # Add firewall rule for WinRM HTTPS
  New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP
  $url = "https://raw.githubusercontent.com/ansible/ansible/6e325d9e4dbdc020eb520a81148866d988a5dbc5/examples/scripts/ConfigureRemotingForAnsible.ps1"
  $file = "$env:temp\ConfigureRemotingForAnsible.ps1"
  (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
  powershell.exe -ExecutionPolicy ByPass -File $file
  Write-Output "WinRM enabled on HTTPS."
} catch {
  $_.Exception.Message
  "Error enabling WinRM on HTTPS."
  Write-Output "Error enabling WinRM on HTTPS."
}
# Check if wazuh-user user exists
if (-not (Get-LocalUser -Name "wazuh-user" -ErrorAction SilentlyContinue)) {
    # Create wazuh-user user
    Write-Output "Creating wazuh-user user"
    $password = ConvertTo-SecureString "ChangeMe" -AsPlainText -Force
    New-LocalUser "wazuh-user" -Password $password -FullName "wazuh-user" -Description "wazuh-user user for remote desktop"

    Write-Output "Adding wazuh-user user to RDP group."
    # Add wazuh-user to Remote Desktop Users group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "wazuh-user"

    Write-Output "Adding wazuh-user user to Administrators group."
    # Add wazuh-user to wazuh-users group
    Add-LocalGroupMember -Group "Administrators" -Member "wazuh-user"
} else {
    Write-Output "wazuh-user user already exists."
    # Set the password for the wazuh-user account
    $admin = [ADSI]"WinNT://./wazuh-user, user"
    $password = "ChangeMe"
    $admin.SetPassword($password)
    $admin.SetInfo()
    Write-Output "wazuh-user password changed successfully."
}
</powershell>
