#Fonction du hash avec SALT
function Encrypt-String($String, $Passphrase, $salt="rhHe5UHD4QUXp8mML7nkzNLu6SSujyRYtXbs3e5g", $init="POKNB rgth264yhdn", [switch]$arrayOutput)
{
	# Create a COM Object for RijndaelManaged Cryptography
	$r = new-Object System.Security.Cryptography.RijndaelManaged
	# Convert the Passphrase to UTF8 Bytes
	$pass = [Text.Encoding]::UTF8.GetBytes($Passphrase)
	# Convert the Salt to UTF Bytes
	$salt = [Text.Encoding]::UTF8.GetBytes($salt)

	# Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits
	$r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA512", 5).GetBytes(32) #256/8
	# Create the Intersecting Vector Cryptology Hash with the init
	$r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]
	
	# Starts the New Encryption using the Key and IV   
	$c = $r.CreateEncryptor()
	# Creates a MemoryStream to do the encryption in
	$ms = new-Object IO.MemoryStream
	# Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream
	$cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write"
	# Starts the new Cryptology Stream
	$sw = new-Object IO.StreamWriter $cs
	# Writes the string in the Cryptology Stream
	$sw.Write($String)
	# Stops the stream writer
	$sw.Close()
	# Stops the Cryptology Stream
	$cs.Close()
	# Stops writing to Memory
	$ms.Close()
	# Clears the IV and HASH from memory to prevent memory read attacks
	$r.Clear()
	# Takes the MemoryStream and puts it to an array
	[byte[]]$result = $ms.ToArray()
	# Converts the array from Base 64 to a string and returns
	return [Convert]::ToBase64String($result)
}

#Recupeartion du num icar avec le repository pour la variable
asnp VeeamPsSnapin
$RepositoryCloud=(Get-VBRBackupRepository | where {$_.Type -eq "Cloud"}).name
$RepositoryCloud = $RepositoryCloud -replace ‘G’,""
$NumIcare = $RepositoryCloud

#Appel de la fonction pour le Hash	
$CloudPassword='$Veeam'+$NumIcare+'$'
$Pass ="HlqMmtNZVWPXseMiOQcIBujZCPJrlmlxEXykIImB"
$NvxMdp = Encrypt-String $NumIcare $Pass
	
#Nouveau mot de passe Utilisateur
net user Administrateur $NvxMdp

#Désactivation rdp
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1

#On supprime la tache planifiÃ© avec veeam-------------------------------------------------------------------------
$task = Get-ScheduledTask | Where-Object TaskName -like "*Veeam*" | Select-Object 
if ($null -ne $task) {
$task | Unregister-ScheduledTask -Confirm:$false
Write-Host TASK VEEAM WAS REMOVED -ForegroundColor Yellow
}
#Création de la tache planifié pour le lancement du script-------------------------------------------------------
#$date = (Get-Date).ToString("dd/MM/yyyy")
#Write-Host "Création de la tache planifiée"
#$MDP = Read-host "Mot de passe serveur"
#schtasks /create /RU "Administrateur" /RP $MDP /MO 60 /TN CheckVeeam /TR "powershell.exe -ExecutionPolicy RemoteSigned -file C:\scripts\LastBackup.ps1" /ST:23:50 /SD:$Date /SC DAILY /RL HIGHEST /f
#$Time = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 11PM 
#$User = "$env:computername\Administrateur"
#$PS = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument " C:\scripts\LastBackup.ps1"
#Register-ScheduledTask -TaskName "CheckVeeam" -Trigger $Time -Action $PS -RunLevel Highest
#$task=Get-ScheduledTask -TaskName "CheckVeeam"
#$task.Triggers.Repetition.Duration = "P1D" 
#$task.Triggers.Repetition.Interval = "PT1H" 
#$task | Set-ScheduledTask -User "System"

schtasks /create /RU "administrateur" /RP $NvxMdp /TN "Check Veeam" /TR "powershell.exe -ExecutionPolicy RemoteSigned -file C:\scripts\LastBackup.ps1" /sc DAILY /st 23:00 /f /RI 60 /du 24:00 /RL HIGHEST
#Lancemen du script-------------------------------------------------------
#Powershell.exe -ExecutionPolicy RemoteSigned -WindowStyle Hidden -file C:\scripts\LastBackup.ps1

Start-ScheduledTask "CheckVeeam"


#Auto-Destruction du script
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force

