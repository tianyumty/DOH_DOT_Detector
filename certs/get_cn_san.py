import json
def get_cn_san(ip_cert):
    ip_domains={}
    for key, value in ip_cert.items():
        domain=[]
        dic_cert=value[0]
        if 'CN' in dic_cert:
            domain.append(dic_cert["CN"])
        if 'SAN' in dic_cert:
            domain.extend(dic_cert["SAN"])
        unique_list = list(set(domain))
        ip_domains[key]=unique_list
    ip_domains_dot = "data/output_certs_domain.json"  # 将文件路径替换为实际的文件路径
    with open(ip_domains_dot, "w") as json_file:
        json.dump(ip_domains, json_file, indent=4)