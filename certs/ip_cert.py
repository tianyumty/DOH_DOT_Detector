import hashlib
from datetime import datetime
from OpenSSL import crypto
import ssl
import socket
import json
import re
BEGIN_X509_CERT = "-----BEGIN CERTIFICATE-----"
END_X509_CERT = "-----END CERTIFICATE-----"
def bytes_to_string(bytes):
    return str(bytes, 'utf-8')
def get_certificate(host, port, timeout=1, ignore_cert_validation=True):
    context = ssl.create_default_context()

    if (ignore_cert_validation):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    connection = socket.create_connection((host, port))
    sock = context.wrap_socket(connection,server_hostname=host)
    sock.settimeout(timeout)

    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()

    return ssl.DER_cert_to_PEM_cert(der_cert)
def parse_multi_certs(certs):
    cert_list = []
    begin_index = certs.find(BEGIN_X509_CERT)

    while (begin_index != -1):
        end_index = certs.find(END_X509_CERT, begin_index) + len(END_X509_CERT)
        cert_list.append(certs[begin_index:end_index])
        begin_index = certs.find(BEGIN_X509_CERT, end_index)

    return cert_list

def x509_name_to_json(x509_name):
    json = { }

    for key, value in x509_name.get_components():
        json.update({ bytes_to_string(key): bytes_to_string(value) })

    return json
def x509_SAN_to_json(x509_cert):
    for ext_index in range(0, x509_cert.get_extension_count(), 1):
        extension = x509_cert.get_extension(ext_index)
        if extension.get_short_name()== b'subjectAltName':
            return str(extension)
def x509_extensions_to_json(x509_cert):
    json = { }
    for ext_index in range(0, x509_cert.get_extension_count(), 1):
        extension = x509_cert.get_extension(ext_index)
        json.update({ bytes_to_string(extension.get_short_name()): str(extension) })

    return json
def parse_x509(cert,ignore_extensions=False):
    x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    cert = {
            "subject": x509_name_to_json(x509_cert.get_subject()),
            "issuer": x509_name_to_json(x509_cert.get_issuer()),
            "has-expired": x509_cert.has_expired(),
            "not-after": str(datetime.strptime(bytes_to_string(x509_cert.get_notAfter()), '%Y%m%d%H%M%SZ')),
            "not-before": str(datetime.strptime(bytes_to_string(x509_cert.get_notBefore()), '%Y%m%d%H%M%SZ')),
            "serial-number": x509_cert.get_serial_number(),
            "serial-number(hex)": hex(x509_cert.get_serial_number()),
            "signature-algorithm": bytes_to_string(x509_cert.get_signature_algorithm()),
            "version": x509_cert.get_version(),
            "pulic-key-length": x509_cert.get_pubkey().bits()
        }

    if (not ignore_extensions):
        cert.update({"extensions": x509_extensions_to_json(x509_cert)})

    return cert
# 定义要连接的IP地址和端口
def get_cert(ip_list):
    try:
        ip_certs = {}
        ips = []
        cn = {}
        san = {}
        for ip in ip_list:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = socket.create_connection((ip,853),timeout=1)
                ssl_sock = context.wrap_socket(connection, server_hostname=ip)
                # 获取服务器证书
                der_certs=[]
                pem_certs=[]
                pem_lists=[]
                ignore_cert_validation= True
                cert_list = parse_multi_certs(get_certificate(ip, 853, ignore_cert_validation=ignore_cert_validation))
                for cert in cert_list:
                    pem_certs.append(cert)
                    certs = {}
                    ignore_extensions = False
                    x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                # 计算证书的 SHA-256 摘要
                    sha256_digest = hashlib.sha256(cert.encode()).hexdigest()
                    certs["sha_256"]=sha256_digest
                # 解析证书并获取CN字段
                    certs["cert"]=parse_x509(cert, ignore_extensions)
                    #print(x509_name_to_json(x509_cert.get_subject()))
                    subject=x509_name_to_json(x509_cert.get_subject())
                    common_name = subject["CN"]
                    certs["CN"]=common_name

                    san_data=[]
                    san_extension=x509_SAN_to_json(x509_cert)
                    if san_extension:
                        dns_name_entries = re.findall(r'DNS:([^\s,]+)', san_extension)
                        for dns_name in dns_name_entries:
                            san_data.append(dns_name)
                        certs["SAN"]=san_data
                    pem_lists.append(certs)
                ip_certs[ip]=pem_lists
                ips.append(ip)
            except socket.error as e:
                # 捕获异常并处理
                if isinstance(e, socket.timeout):
                    error_info = f"{ip} 连接超时: {e}"
                    #print(f"{ip}连接超时: {e}")
                elif isinstance(e, ConnectionRefusedError):
                    error_info =f"{ip}连接被拒绝: {e}"
                    #print(f"{ip}连接被拒绝: {e}")
                elif isinstance(e, socket.gaierror):
                    error_info =f"{ip}DNS解析错误: {e}"
                    #print(f"{ip}DNS解析错误: {e}")
                else:
                    error_info = f"{ip}发生未知网络错误: {e}"
                    #print(f"{ip}发生未知网络错误: {e}")
            except socket.timeout as e:
                error_info = f"{ip}连接超时: {e}"
                #print(f"{ip}连接超时: {e}")
            except ConnectionRefusedError as e:
                error_info=f"{ip}连接被拒绝: {e}"
                #print(f"{ip}连接被拒绝: {e}")
            except socket.gaierror as e:
                error_info=f"{ip}DNS解析错误: {e}"
                #print(f"{ip}DNS解析错误: {e}")
            except ssl.SSLError as e:
                error_info=f"{ip}SSL错误: {e}"
                #print(f"{ip}SSL错误: {e}")
            except Exception as ex:
                error_info=f"{ip}发生其他异常: {ex}"
                #print(f"{ip}发生其他异常: {ex}")
            finally:
                # 关闭 socket 连接（无论是否发生异常都应该关闭）
                if 'ssl_sock' in locals():
                    ssl_sock.close()
    except Exception as ex:
        error_info=f"发生异常: {ex}"
        #print(f"发生异常: {ex}")
    cert_to_hostname = "data/output_certs.json"  # 对应的是ip_certi
    with open(cert_to_hostname, "w") as json_file:
        json.dump(ip_certs, json_file, indent=4)
    json_file.close()
    test_ips = {"ip": ips}
    cert_to_ip = "data/output_certs_ip.json"  # 是只有ip的结果
    with open(cert_to_ip, "w") as json_file:
        json.dump(test_ips, json_file, indent=4)
    json_file.close()
