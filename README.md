# DOH_DOT_Detector
Stand alone application for DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) detection dns-over-https dns-over-tls x509Parser doh dot

# Model
## certs
1) Obtain the x509 certificate of the domain name and save the result to `/data/output_certs.json`
2) Extract the domain name of `cn` and `san` fields from the certificate and save the result to `/data/output_certs_domain.json`

## send_pcap
1) Construct `GET` and `POST` requests with `SNI` and `GET` and `POST` requests without `SNI`
2) The query path of doh includes
    `/dns-query
     /resolver
     /doh
     /ads
     /query`
3) Save the domain name corresponding to the successful doh request, located in `data/ip_test.json` (if it can be accessed only by IP, we only keep IP)

# Prerequisites
Python packages needed for running DoHlyzer are listed in `requirements.tx`t file. You can install them (preferably in virtualenv) by:
`pip install -r requirements.txt`
