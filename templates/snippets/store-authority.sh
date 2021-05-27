# Save CA certificate
mkdir -p /etc/certidude/authority/{{ authority.namespace }}/
test -e /etc/certidude/authority/{{ authority.namespace }}/ca_cert.pem \
 || cat << EOF > /etc/certidude/authority/{{ authority.namespace }}/ca_cert.pem
{{ authority.certificate.blob }}EOF
