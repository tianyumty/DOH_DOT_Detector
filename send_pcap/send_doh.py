import dns.message
import dns.query
import base64
import requests
import httpx
#构造不包含sni的请求

#构造get、POST、Json请求   使用不同的路径
def get_check(value):
    if value:
        delay_seconds = 5
        try:
            domain = "google.com"
            rr = "A"
            message = dns.message.make_query(domain, rr)
            dns_req = base64.b64encode(message.to_wire()).decode("UTF8").rstrip("=")
            url="https://"+str(value)+"/dns-query"
            r = requests.get(url + "?dns=" + dns_req, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      },timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/resolve"
            r = requests.get(url + "?dns=" + dns_req, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/ads"
            r = requests.get(url + "?dns=" + dns_req, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/doh"
            r = requests.get(url + "?dns=" + dns_req, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/query"
            r = requests.get(url + "?dns=" + dns_req, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
        except httpx.ConnectError as e:
            #err_cnt = err_cnt + 1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except httpx.ConnectTimeout as e:
            #err_cnt = err_cnt + 1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except requests.exceptions.RequestException as e:
            #err_cnt=err_cnt+1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except dns.exception.DNSException as e:
            #err_cnt = err_cnt + 1
            if r is not None:
                r.close()
            #print(f"ID_{value}DNS解析过程中发生异常: {e}")
            return False
        except ValueError as e:
            # 捕获异常并处理
            #err_cnt = err_cnt + 1
            if r is not None:
                r.close()
            #print(f"ID_{value}Caught an error: {e}")
            return False

def post_check(value):
    if value:
        delay_seconds = 5
        try:
            domain = "google.com"
            rr = "A"
            message = dns.message.make_query(domain, rr)
            dns_query = message.to_wire()
            #dns_req = base64.b64encode(message.to_wire()).decode("UTF8").rstrip("=")
            url="https://"+str(value)+"/dns-query"
            r = requests.post(url ,data=dns_query, verify=False,
                             headers={"Content-type": "application/dns-message",
                                      "Accept": "application/dns-message"
                                      },timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/resolve"
            r = requests.post(url, data=dns_query, verify=False,
                              headers={"Content-type": "application/dns-message",
                                       "Accept": "application/dns-message"
                                       }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/ads"
            r = requests.post(url, data=dns_query, verify=False,
                              headers={"Content-type": "application/dns-message",
                                       "Accept": "application/dns-message"
                                       }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/doh"
            r = requests.post(url, data=dns_query, verify=False,
                              headers={"Content-type": "application/dns-message",
                                       "Accept": "application/dns-message"
                                       }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
            url = "https://" + str(value) + "/query"
            r = requests.post(url, data=dns_query, verify=False,
                              headers={"Content-type": "application/dns-message",
                                       "Accept": "application/dns-message"
                                       }, timeout=5)
            if r.status_code == 200:
                dns_response = dns.message.from_wire(r.content)
                answer_list = dns_response.answer
                if not answer_list:
                    #print(f"ID_{value}:DNS响应结果为空")
                    if r is not None:
                        r.close()
                    return False
                else:
                    return True
            else:
                #print(f"{value}请求失败，状态码: {r.status_code}")
                if r is not None:
                    r.close()
                return False
            if r is not None:
                r.close()
        except httpx.ConnectError as e:
            #err_cnt = err_cnt + 1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except httpx.ConnectTimeout as e:
            #err_cnt = err_cnt + 1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except requests.exceptions.RequestException as e:
            #err_cnt=err_cnt+1
            #print(f"ID_{value}请求发生异常: {e}")
            return False
        except dns.exception.DNSException as e:
            #err_cnt = err_cnt + 1
            if r is not None:
                r.close()
            #print(f"ID_{value}DNS解析过程中发生异常: {e}")
            return False
        except ValueError as e:
            # 捕获异常并处理
            #err_cnt = err_cnt + 1
            if r is not None:
                r.close()
            #print(f"ID_{value}Caught an error: {e}")
            return False


