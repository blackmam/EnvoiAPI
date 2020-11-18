#Désactivation rdp
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
#Nouveau mot de passe Utilisateur
$Motdepasse ='rZwNCI4ijjULepw24g9A'
net user Administrateur $Motdepasse
