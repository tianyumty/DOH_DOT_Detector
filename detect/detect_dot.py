import json
from send_pcap import send_dot


#根据论文的实验探测实验表明，dot支持端口探测，不太需要sni，这里的dot探测就没有包含sni
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
def process_dot(ip_file,  output_doh_file):
    ips = read_ips_from_file(ip_file)
    dot_list=[]
    for key in ips:
        if send_dot.test_dot(key, 853):
            dot_list.append(key)
    save_list_to_txt(output_doh_file, dot_list)
