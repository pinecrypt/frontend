[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

{% include "snippets/update-trust.ps1" %}

{% include "snippets/request-client.ps1" %}

# Set up IPSec VPN tunnel to {{ authority.namespace }}
Remove-VpnConnection -AllUserConnection -Force "IPSec to {{ authority.namespace }}"
Add-VpnConnection `
    -Name "IPSec to {{ authority.namespace }}" `
    -ServerAddress {{ authority.namespace }} `
    -AuthenticationMethod MachineCertificate `
    -EncryptionLevel Maximum `
    -SplitTunneling `
    -TunnelType ikev2 `
    -PassThru -AllUserConnection

# Harden VPN configuration
Set-VpnConnectionIPsecConfiguration `
    -ConnectionName "IPSec to {{ authority.namespace }}" `
    -AuthenticationTransformConstants GCMAES128 `
    -CipherTransformConstants GCMAES128 `
    -EncryptionMethod AES256 `
    -IntegrityCheckMethod SHA384 `
    -DHGroup {% if authority.certificate.algorithm == "ec" %}ECP384{% else %}Group14{% endif %} `
    -PfsGroup {% if authority.certificate.algorithm == "ec" %}ECP384{% else %}PFS2048{% endif %} `
    -PassThru -AllUserConnection -Force

{#
AuthenticationTransformConstants - ESP integrity algorithm, one of: None MD596 SHA196 SHA256128 GCMAES128 GCMAES192 GCMAES256
CipherTransformConstants - ESP symmetric cipher, one of: DES DES3 AES128 AES192 AES256 GCMAES128 GCMAES192 GCMAES256
EncryptionMethod - IKE symmetric cipher, one of: DES DES3 AES128 AES192 AES256
IntegrityCheckMethod - IKE hash algorithm, one of: MD5 SHA196 SHA256 SHA384
DHGroup = IKE key exchange, one of: None Group1 Group2 Group14 ECP256 ECP384 Group24
PfsGroup = ESP key exchange, one of: None PFS1 PFS2 PFS2048 ECP256 ECP384 PFSMM PFS24
#}
