Add a user on windows:
net user $username $password /add

Add a user to the “Remote Desktop Users” group:
net localgroup "Remote Desktop Users" $username /add

Make a user an administrator:
net localgroup administrators $username /add

Disable Windows firewall on newer versions:
NetSh Advfirewall set allprofiles state off

Disable windows firewall on older windows:
netsh firewall set opmode disable
