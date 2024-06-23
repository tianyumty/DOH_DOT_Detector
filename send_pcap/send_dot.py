import socket
import ssl
import dns.message
import dns.query
# 创建DNS查询消息对象
domain = "baidu.com"  # 要解析的域名
rr = dns.rdatatype.A  # A记录是IPv4地址
q = dns.message.make_query(domain, rr)
is_empty= True
def test_dot(dot_server_ip,dot_server_port):
    try:
        # 创建一个普通的socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.connect((dot_server_ip, dot_server_port))
        # 创建一个不验证SSL证书的SSL上下文
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        response = dns.query.tls(q=q, where=dot_server_ip, port=dot_server_port,timeout=2,ssl_context=context)
        if response:
            return True
        else:
            return False
    except dns.exception.Timeout:
        return False
        #print("DNS Query Timed Out")  # 捕获超时异常
    except dns.exception.DNSException as e:
        return False
        #print(f"DNS Query Error: {e}")  # 捕获其他DNS异常
    except Exception as e:
        return False
        #print(f"An unexpected error occurred: {e}")  # 捕获其他未知异常
    return False
