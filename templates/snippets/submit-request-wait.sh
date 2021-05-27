# Submit CSR and save signed certificate
curl --cert-status -f -L -H "Content-type: application/pkcs10" \
    --cacert /etc/certidude/authority/{{ authority.namespace }}/ca_cert.pem \
    --data-binary @/etc/certidude/authority/{{ authority.namespace }}/host_req.pem \
    -o /etc/certidude/authority/{{ authority.namespace }}/host_cert.pem \
    'https://{{ authority.namespace }}:8443/api/request/?wait=yes'
