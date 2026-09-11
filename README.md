# Web-Scanner 漏洞扫描器项目
一个从零开始编写的 Web 安全学习与实践工具集，涵盖目录扫描、漏洞检测、渗透实战等多个方向，用于学习和实践安全开发。

## 已实现模块
### 1. 目录扫描器（核心主扫描器）
- 多线程并发扫描，速度可配置
- 从外部字典加载路径
- 支持自定义HTTP状态码记录（200，403，301，302）
- 结果持久化存储到SQLite数据库
- 自动生成扫描报告（TXT格式）
- 历史记录查询与统计分析
- 核心文件：`day6_scanner_v3.py`、`day3_utils.py`、`day5_db_utils.py`、`day5_report.py`

### 2. SQL 注入检测与脱库模块
- 注入点自动检测（字符型、宽字节、数字型）
- 支持四种脱库方式，按效率自动降级：联合注入 → 报错注入 → 布尔盲注 → 时间盲注
- 核心文件：`scanner/modules/sql_injection.py`

### 3. 命令注入检测模块
- 支持 GET/POST 参数传递检测
- 靶场注入探测实战
- 相关文件：`check_alive.py`、`command_injection_target.py`

### 4. CSRF 漏洞实战
- curl 复现 CSRF 攻击
- 靶场环境与防御方法记录
- 相关文件：`csrf_attack.html`、`csrf_target.py`

### 5. HTTP 协议基础练习
- HTTP 请求构造、参数传递、调试实践
- 相关文件：`day1_*.py`、`day2_*.py`、`day3_*.py`

## 技术栈
- Python
- SQLite
- 多线程（ThreadPoolExecutor）
- 命令行参数解析（argparse）
- requests 网络请求库

## 使用示例
### 目录扫描模式
```bash
python day6_scanner_v3.py -u "http://目标地址" -d dict.txt -t 10


## 作者
[Wzzm-123] - 安全开发学习者