import requests
import time
from concurrent.futures import  ThreadPoolExecutor
#测试目标：测试一个响应速度较慢的网站
url = "http://httpbin.org/delay/1"#这个接口会故意延迟一秒再回
#=======单线程版本========
def single_thread_test(n):
    start = time.time()
    for i in range(n):
        requests.get(url,timeout = 5)
        print(f"单线程：完成第{i+1}个请求")
    end = time.time()
    print(f"单线程总耗时：{end - start :.2f}秒")
#=========多线程版本========
def multi_thread_test(n):
    start = time.time()
    with ThreadPoolExecutor(max_workers=n) as excuter:
        #一次性提交所有任务
        futures = [excuter.submit(requests.get,url,timeout = 5) for _ in range(n)]
        #等待所有任务完成
        for i ,future in enumerate(futures):
            future.result
            print(f"多线程：完成第{i+1}个请求")
    end = time.time()
    print(f"多线程总耗时：{end - start :.2f}秒")
#测试发送五个请求
print("===单线程测试===")
single_thread_test(5)
print("===多线称测试===")
multi_thread_test(5)