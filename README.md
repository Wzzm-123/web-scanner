# Web漏洞扫描器

一个从零开始编写的轻量级Web目录扫描器，用于学习和实践安全开发。

## 功能
- 多线程并发扫描，速度可配置
- 从外部字典加载路径
- 支持自定义HTTP状态码记录（200, 403, 301, 302）
- 结果持久化存储到SQLite数据库
- 自动生成扫描报告（TXT格式）
- 历史记录查询与统计分析

## 使用方法
### 扫描模式
python day6_scanner_v3.py -u "http://目标地址" -d dict.txt -t 10

### 搜索历史记录
python day6_scanner_v3.py -s "admin"

## 技术栈
- Python
- SQLite
- 多线程 (ThreadPoolExecutor)
- 命令行参数解析 (argparse)

## 项目结构
- day3_utils.py: HTTP请求工具库
- day5_db_utils.py: 数据库操作工具箱
- day5_report.py: 报告生成器
- day6_scanner_v3.py: 主扫描器（V0.3）
- dict.txt: 扫描字典
- scan_report.txt: 输出的扫描报告

## 作者
[Wzzm-123] - 安全开发学习者