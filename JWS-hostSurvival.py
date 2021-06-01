'''
    JWS-hostSurvival是JWS系统的内网ip存活网段收集模块。
                                                    by-jammny
'''
from threading import Thread
from queue import Queue
from time import time
from sys import stdout
from colorama import init, Fore
import argparse, os

class CheckAlive():
    def __init__(self):
        self.result = []

    # Ping主机，判断存活
    def ping(self, queue):
        while not queue.empty():
            ip = queue.get()
            # 命令执行，返回str格式输出结果
            result = os.popen("ping -n 1 {}".format(ip))
            try:
                data = result._stream.buffer.read().decode(encoding='gbk')
            except:
                data = result._stream.buffer.read().decode(encoding='utf-8')
            if "TTL" in data:
                stdout.write(Fore.GREEN + "[+] {} UP\n".format(ip))
                self.result.append("{}\n".format(ip))
            else:
                pass

    # 写入结果
    def save_result(self, type):
        with open("result/{}.txt".format(type), mode='w', encoding='utf-8') as f:
            for result in self.result:
                f.write(result)

    # 添加数据到队列
    def add_queue(self, type):
        queue = Queue()
        # C类
        if type == "C":
            for c in range(256):
                queue.put("192.168.{}.1".format(c))
        # B类
        elif type == "B":
            for b in range(16,32):
                for c in range(256):
                    queue.put("172.{}.{}.1".format(b,c))
        # A类
        elif type == "A":
            for b in range(256):
                for c in range(256):
                    queue.put("10.{}.{}.1".format(b,c))
        # IP
        else:
            target = type
            list = target.split('.')
            ip = "{}.{}.{}.".format(list[0], list[1], list[2])
            for i in range(1, 256):
                queue.put(ip + "{}".format(i))
        return queue

    def run(self, type, thread_count):
        print(Fore.MAGENTA + "[+] 主机存活探测开始!")
        start = time()
        queue = self.add_queue(type)
        thread_pool = [] # 定义线程任务池
        # 创建多线程
        for _ in range(thread_count):
            task = Thread(target=self.ping, args=[queue])
            thread_pool.append(task)
        # 开始多线程
        for i in range(thread_count):
            thread_pool[i].start()
        for i in range(thread_count):
            thread_pool[i].join()
        end = time()
        print(Fore.MAGENTA + "[+] 总计存活：{}".format(len(self.result)))
        print(Fore.MAGENTA + "[+] 任务耗时：{}".format(end - start))
        # 判读目录
        if os.path.exists("result"):
            pass
        else:
            os.mkdir("result")
        # 写入结果
        self.save_result(type)
        print(Fore.MAGENTA + "[+] 结果保存路径：./result/{}.txt".format(type))

if __name__ == "__main__":
    init(autoreset=True)  # 初始化，并且设置颜色设置自动恢复
    print(Fore.MAGENTA + r'''
     _    _           _    _____                  _            _  
    | |  | |         | |  / ____|                (_)          | | 
    | |__| | ___  ___| |_| (___  _   _ _ ____   _____   ____ _| | 
    |  __  |/ _ \/ __| __|\___ \| | | | '__\ \ / / \ \ / / _` | | 
    | |  | | (_) \__ \ |_ ____) | |_| | |   \ V /| |\ V / (_| | | 
    |_|  |_|\___/|___/\__|_____/ \__,_|_|    \_/ |_| \_/ \__,_|_|    
                                                                   ——jammny 2021.5.22                                            
       ''')
    parser = argparse.ArgumentParser(description='用法：python3 JWS_hostSurvival.py <type>')
    parser.add_argument('--type', '-p', type=str, help="C类为C，B类为B，A类为A, --type=C")
    parser.add_argument('--thread', '-t', type=str, help="默认线程100，--thread=150")
    parser.add_argument('--detail', '-d', type=str, help="扫描D段存活IP, --deaile=192.168.30.1")
    args = parser.parse_args()
    scan = CheckAlive()
    thread_count = 100   # 默认线程
    if args.thread:
        thread_count = args.thread
    if args.type:
        scan.run(args.type, thread_count)
    elif args.detail:
        scan.run(args.detail, thread_count)
