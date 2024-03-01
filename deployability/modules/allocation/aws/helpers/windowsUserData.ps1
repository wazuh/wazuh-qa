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
New-LocalUser "Administrator" -Password ChangeMe -FullName "Administrator" -Description "Administrator user for remote desktop"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrator"
# Set Administrator user to administrator group
Add-LocalGroupMember -Group "Administrators" -Member "Administrator"
# Set the password for the Administrator account
$admin = [ADSI]"WinNT://./Administrator, user"
$admin.SetPassword("ChangeMe")
$admin.SetInfo()
</powershell>