# author: fe1w0
import time 
import HackRequests
import json
import config
import sys
import os
import platform
import traceback
import ipaddress
from rich.console import Console

def now_time():
    # 获取当前时间戳和一小时前的时间戳
    current_timestamp = int(time.time() * 1000)
    past_timestamp = current_timestamp - 1000 * 60 * config.monitor_config["select_time"]
    return current_timestamp, past_timestamp

def day_time():
    # 获取当天整天时间
    past_timestamp = int(time.time()/(60 * 60 * 24)) * (60 * 60 * 24) * 1000 - 8 * 60 * 60 *1000
    current_timestamp = past_timestamp + 24 * 60 * 60 * 1000 - 1000
    return current_timestamp, past_timestamp        
        
def is_len(ip):
    if not ip:
        return True
    try:
        if ipaddress.ip_address(ip.strip()).is_private:
            return True
        else:
            return False
    except:
        print("[!] Error", ip)
        traceback.print_exc()
        return False
        
def print_warning_log(item):
    # 打印攻击警告信息
    console = Console()
    if config.monitor_config["check_len"]:
        if not is_len(item["attack_sip"]):
            console.bell()
            console.print("[*] Warning ⚠️ : Threat", item["type"], item["threat_name"], "attack_sip [bold red]" + item["attack_sip"] + "[/bold red]"
            , "aalarm_sip", item["alarm_sip"], "XFF", item["x_forwarded_for"], "repeat_count", item["repeat_count"]
            , "Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["access_time"]/1000)))
        elif not is_len(item["x_forwarded_for"].split(",")[0]):
            console.bell()
            console.print("[*] Warning ⚠️ : Threat", item["type"], item["threat_name"], "attack_sip", item["attack_sip"],
            "aalarm_sip", item["alarm_sip"], "XFF [bold red]" + item["x_forwarded_for"] + "[/bold red]", "repeat_count", item["repeat_count"]
            , "Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["access_time"]/1000)))
        else: 
            console.print("[*] Warning ⚠️ : Threat", item["type"], item["threat_name"], "attack_sip", item["attack_sip"],
            "alarm_sip", item["alarm_sip"], "XFF", item["x_forwarded_for"], "repeat_count", item["repeat_count"]
            , "Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["access_time"]/1000)))
    else:
        console.bell()
        console.print("[*] Warning ⚠️ : Threat", item["type"], item["threat_name"], "attack_sip", item["attack_sip"],
            "alarm_sip", item["alarm_sip"], "XFF", item["x_forwarded_for"], "repeat_count", item["repeat_count"]
            , "Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["access_time"]/1000)))


def print_handled_log(item):
    # 打印标灰的日志信息
    console = Console()
    if config.monitor_config["disable_print_handled"]:
        return
    console.print("[+] Handled 🌟: threat_name", item["threat_name"], "attack_sip", item["attack_sip"],
        "alarm_sip", item["alarm_sip"],  "XFF", item["x_forwarded_for"], "repeat_count", item["repeat_count"], 
        "Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["access_time"]/1000)))
        
def get_new_csrf_token(user_session, debug=False):
    # 获取用户的具体token
    raw = """
GET /skyeye/v1/system/device/city-geo-info HTTP/2
Host: {server_ip}
Cookie: session={user_session}
Sec-Ch-Ua: " Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 Chrome/103.0.5060.134 Edg/103.0.1264.71
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close""".format(server_ip=config.monitor_config['server_ip'], user_session=user_session)
    hack = HackRequests.hackRequests()
    result =  json.loads(hack.httpraw(raw=raw, ssl=True).text())
    if debug:
        print(raw)
        print(result)
    token = result["error"]["token"]
    message = result["error"]["message"]
    # 检测是否session是否正确
    if  message == "未登陆或登陆超时！":
        print("[!] 登录失败，请修改配置文件中的用户session，并确保正确！")
        sys.exit(1)
    elif message == "无权限访问！":
        return token


def get_current_log(user_session, current_timestamp, past_timestamp, search_limit, csrf_token, debug=False):
    # 获得当前一小时内的日志信息
    raw = """
GET /skyeye/v1/alarm/alarm/list?offset=1&limit={search_limit}&order_by=access_time:desc&is_accurate=0&data_source=1&host_state=&alarm_sip=&attack_sip=&ioc=&asset_group=&threat_name=&attack_stage=&branch_id=&x_forwarded_for=&is_web_attack=&host=&status_http=&alarm_source=&staff_name=&uri=&alert_rule=&sip=&dip=&sport=&dport=&dst_mac=&src_mac=&vlan_id=&proto=&serial_num=&threat_type=&hazard_level=&status=&attck_org=&attck=&alarm_id=&attack_dimension=&is_white=0&focus_label=&marks=&asset_ip=&user_label=&start_time={past_timestamp}&end_time={current_timestamp}&csrf_token={csrf_token}&r=0.15947662660939077 HTTP/2
Host: {server_ip}
Cookie: session={user_session}
Sec-Ch-Ua: " Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 Chrome/103.0.5060.134 Edg/103.0.1264.71
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close""".format(server_ip=config.monitor_config['server_ip'], search_limit=search_limit, past_timestamp=past_timestamp, csrf_token=csrf_token
                            , current_timestamp=current_timestamp, user_session=user_session)        
    if debug:
        print(raw)
    hack = HackRequests.hackRequests()
    result =  hack.httpraw(raw, ssl=True)
    # parse json reslut 
    log  = json.loads(result.text())
    if debug:
        print(log)
    return log

def handle_log_remote(log_item, csrf_token, user_session, debug=False):
    # 标灰 log_item，后期改用多线程
    format_raw = """
GET /skyeye/v1/alarm/alarm/user-label?data_source=1&user_label=1&alarm_ids={id}&csrf_token={csrf_token}&r=0.4259559188144866 HTTP/2
Host: {server_ip}
Cookie: session={user_session}
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: " Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 Chrome/103.0.5060.134 Edg/103.0.1264.71
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close""".format(server_ip=config.monitor_config['server_ip'], id=log_item["id"], csrf_token=csrf_token, user_session=user_session)
    hack = HackRequests.hackRequests()
    result =  hack.httpraw(format_raw, ssl=True)
    if debug:
        print(format_raw)
        print(result.text())
    
    
def _callback(r:HackRequests.response):
    # 从回调函数取出结果，参数r是response结果
    if config.monitor_config["debug"]:
        print(r.text())
    return 

def handle_log_remote_thread(handle_list, csrf_token, user_session, debug=False):
    threadpool = HackRequests.threadpool(threadnum=10,callback=_callback,timeout=20)
    # 可设置http访问的超时时间，不设置则默认为10s。线程数量[threadnum]设置根据自己电脑配置设置，默认为10,值越大线程越多同一秒访问的网站数量也越多。
    raw = """
GET /skyeye/v1/alarm/alarm/user-label?data_source=1&user_label=1&alarm_ids={id}&csrf_token={csrf_token}&r=0.4259559188144866 HTTP/2
Host: {server_ip}
Cookie: session={user_session}
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: " Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 Chrome/103.0.5060.134 Edg/103.0.1264.71
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close"""
    for log_item in handle_list:
        if debug:
            print(raw)
        raw = raw.format(server_ip=config.monitor_config['server_ip'], id=log_item["id"], csrf_token=csrf_token, user_session=user_session)
        print_handled_log(item=log_item)
        threadpool.httpraw(raw, ssl=True)
    threadpool.run()
    
def handle_log_remote_pool(handle_list, csrf_token, user_session, debug=False):
    # 利用 pool 实现完全处理
    while( len(handle_list) != 0):
        log_item = handle_list[0]
        hack = HackRequests.hackRequests()
        raw = """
GET /skyeye/v1/alarm/alarm/user-label?data_source=1&user_label=1&alarm_ids={id}&csrf_token={csrf_token}&r=0.4259559188144866 HTTP/2
Host: {server_ip}
Cookie: session={user_session}
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: " Not;A Brand";v="99", "Microsoft Edge";v="103", "Chromium";v="103"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 Chrome/103.0.5060.134 Edg/103.0.1264.71
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close"""
        raw = raw.format(server_ip=config.monitor_config['server_ip'], id=log_item["id"], csrf_token=csrf_token, user_session=user_session)
        result = json.loads(hack.httpraw(raw, ssl=True).text())
        try:
            if result["data"]["status"] == 1000:
                print_handled_log(item=log_item)
        except Exception as e:
            print("[!] Error", e, "\n", raw)
            traceback.print_exc()
        handle_list.pop(0)

def search_log(log_items, monitor_config, debug=False):
    print("[+] Start Search and Handle item :")
    # 更新 csrf_token
    user_session = monitor_config['session']
    csrf_token = get_new_csrf_token(user_session, debug=debug)
    # 标灰的对象是 ignor_threat, reported_threats
    handle_list = []
    warning_list = []
    # search_itens_counter = 0
    for item in log_items:
        # 
        # if item["x_forwarded_for"].split(", ")[0] == "103.144.3.103":
        #     print("debug")
        # ignore_white_list
        if item["attack_sip"] in monitor_config["white_list"] or item["x_forwarded_for"].split(",")[0] in monitor_config["white_list"]:
            handle_list.append(item)
            continue
        # ignore_threat
        if item["threat_name"] in monitor_config["ignor_threat"]:
            handle_list.append(item)
        # reported_threats
        elif item["type"] in monitor_config["warning_types"]:
            if item["threat_name"] in monitor_config["reported_threat_names"]:
                for threat_name in monitor_config["reported_threat_names"]:
                    if item["threat_name"] == threat_name:
                        try:
                            if (item["attack_sip"] in monitor_config["reported_threats"][threat_name] 
                                or item["x_forwarded_for"].split(",")[0] in monitor_config["reported_threats"][threat_name]):
                                handle_list.append(item)
                            else:
                                warning_list.append(item)
                                # print_warning_log(item=item)
                        except :
                            traceback.print_exc()
                            continue
            else:
                warning_list.append(item)
                # print_warning_log(item=item)
    print("[+] Number of items have warned:", len(warning_list))
    # sort handle_list
    handle_list = sorted(handle_list, key=lambda item: (item["threat_name"], item["attack_sip"]))
    # sort warning
    warning_list = sorted(warning_list, key=lambda item: (item["attack_sip"], item["threat_name"]))
    for item in warning_list:
        print_warning_log(item=item)
    print("[+] Number of items have processed:", len(handle_list))
    # handle_log_remote_thread(handle_list=handle_list, csrf_token=csrf_token, user_session=user_session, debug=debug)
    handle_log_remote_pool(handle_list=handle_list, csrf_token=csrf_token, user_session=user_session, debug=debug)
    # for item in handle_list:
    #     handle_log_remote(log_item=item, csrf_token=csrf_token, user_session=user_session, debug=debug)
    #     print_handled_log(item=item)

def print_form_feed():
    # 根据不同的系统，实现换页刷新
    # windows 上好像还是有问题
    console = Console()
    if "Windows" in platform.platform().lower():
        console.clear()
    else:
        console.clear()
        # os.system("tput reset")

def monitor(monitor_config):
    search_limit = monitor_config["search_limit"]
    debug = monitor_config["debug"]
    current_timestamp, past_timestamp = now_time()
    user_session = monitor_config["session"]
    try:
        csrf_token = get_new_csrf_token(user_session, debug=debug)
        log = get_current_log(user_session=user_session, current_timestamp=current_timestamp
                              , past_timestamp=past_timestamp, search_limit=search_limit
                              , csrf_token=csrf_token, debug=debug)
        number_log = int(log["data"]["total"])
        log_items = log["data"]["items"]
        print_form_feed()
        print("[+] Number of logs: ", number_log)
        if (number_log > search_limit):
            print("[*] Warning: search_limit is small!")
        # search and handle
        search_log(log_items=log_items, monitor_config=monitor_config, debug=debug)
        print("[+] END Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_timestamp/1000)))
        print("=========================================================================================")
    except Exception as e:
        print("[!] Error", e)
        traceback.print_exc()
