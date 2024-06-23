import json
from certs import get_cn_san, ip_cert
from send_pcap import send_doh


def read_ips_from_file(file_path):
    with open(file_path, 'r') as file:
        ips = [ip.strip() for ip in file.readlines()]
    return ips
def save_list_to_txt(file_path, data_list):
    try:
        with open(file_path, 'w') as file:
            for item in data_list:
                file.write(f"{item}\n")
        print(f"列表已成功保存到 {file_path}")
    except IOError as e:
        print(f"文件操作失败: {e}")


def load_json(file_path):
    with open(file_path, "r") as json_file:
        data = json.load(json_file)
    return data


def save_json(file_path, data):
    with open(file_path, "w") as json_file:
        json.dump(data, json_file, indent=4)


def process_doh(ip_file,  output_doh_file):
    ips = read_ips_from_file(ip_file)
    ip_cert.get_cert(ips)  # 获取IP的证书
    json_cert_file = "data/output_certs.json"
    cert_data = load_json(json_cert_file)
    get_cn_san.get_cn_san(cert_data)  # 获取证书中的域名信息
    json_domain_file = "data/output_certs_domain.json"
    domain_data = load_json(json_domain_file)
    ip_dohname = {}
    doh_list = []
    output_ip_file = "data/ip_test.json"
    for key, value in domain_data.items():
        if send_doh.get_check(str(key)):
            ip_dohname[key] = str(key)
            doh_list.append(key)
            continue
        else:
            if send_doh.post_check(key):
                ip_dohname[key] = value
                doh_list.append(key)
                continue
        for word in value:
            if "*" in word:
                string = str(word.replace("*", "dns"))
                if send_doh.get_check(string):
                    ip_dohname[key] = value
                    doh_list.append(key)
                    continue
                else:
                    if send_doh.post_check(string):
                        ip_dohname[key] = value
                        doh_list.append(key)
                        continue
                string2 = str(word.replace("*", "doh"))
                if send_doh.get_check(string2):
                    ip_dohname[key] = value
                    doh_list.append(key)
                    continue
                else:
                    if send_doh.post_check(string2):
                        ip_dohname[key] = value
                        doh_list.append(key)
                        continue
            else:
                if send_doh.get_check(word):
                    ip_dohname[key] = value
                    doh_list.append(key)
                    continue
                else:
                    if send_doh.post_check(word):
                        ip_dohname[key] = value
                        doh_list.append(key)
                        continue

    save_json(output_ip_file, ip_dohname)
    save_list_to_txt(output_doh_file, doh_list)
