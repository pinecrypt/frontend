cat > /etc/ipsec.conf << EOF
config setup
    strictcrlpolicy=yes

ca {{ authority.namespace }}
    auto=add
    cacert=/etc/certidude/authority/{{ authority.namespace }}/ca_cert.pem

conn client-to-site
    auto=start
    right={{ authority.namespace }}
    rightsubnet=0.0.0.0/0
    rightca="{{ session.authority.certificate.distinguished_name }}"
    left=%defaultroute
    leftcert=/etc/certidude/authority/{{ authority.namespace }}/host_cert.pem
    leftsourceip=%config
    leftca="{{ session.authority.certificate.distinguished_name }}"
    keyexchange=ikev2
    keyingtries=%forever
    dpdaction=restart
    closeaction=restart
    ike=aes256-sha384-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    esp=aes128gcm16-aes128gmac-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
EOF

echo ": {% if session.authority.certificate.algorithm == "ec" %}ECDSA{% else %}RSA{% endif %} {{ authority.namespace }}.pem" > /etc/ipsec.secrets

ipsec restart
