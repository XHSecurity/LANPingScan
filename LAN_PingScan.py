import socket
import subprocess
import platform
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
from rich import box

# 创建控制台输出对象
console = Console()


# Ping一个IP，返回是否存活以及响应时间
def ping_ip(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]  # IP对象转为字符串

    start_time = time.time()
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        duration = time.time() - start_time
        if "ttl=" in output.lower():  # 基于ping结果判断是否存活
            return True, duration
        else:
            return False, None
    except subprocess.CalledProcessError:
        return False, None


# 扫描一个IP范围，使用多线程并发处理
def scan_ips_concurrent(ip_range, max_workers=100):
    # 创建表格显示扫描结果
    table = Table(title="存活IP扫描结果", box=box.DOUBLE)
    table.add_column("序号", justify="right", style="cyan", no_wrap=True)
    table.add_column("目标IP", justify="left", style="magenta")
    table.add_column("响应时间 (秒)", justify="center", style="green")

    results = []

    # 使用Rich显示进度条
    with Progress() as progress:
        task = progress.add_task("[green]扫描中...", total=len(ip_range))

        # 使用线程池并发ping多个IP
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(ping_ip, ip): ip for ip in ip_range}

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_alive, duration = future.result()
                    if is_alive:
                        # 存活的IP添加到结果中，按存活目标顺序编号
                        duration_str = f"{duration:.2f}"
                        results.append((str(ip), duration_str))

                    # 更新进度条
                    progress.update(task, advance=1)

                except Exception as e:
                    console.print(f"[red]扫描 {ip} 时出错: {e}[/red]")

    # 输出存活的目标
    if results:
        for index, result in enumerate(results, start=1):
            # 添加存活IP到表格中，按顺序编号
            table.add_row(str(index), result[0], result[1])
        console.print(table)
    else:
        console.print("[bold red]没有找到存活的目标。[/bold red]")


if __name__ == "__main__":
    # 提示用户输入目标网段 (如: 192.168.1.1/24)
    cidr_input = input("请输入目标IP网段 (CIDR格式，如192.168.1.1/24): ")

    try:
        # 解析CIDR输入并生成IP地址范围
        network = ipaddress.ip_network(cidr_input, strict=False)
        ip_range = list(network.hosts())  # 排除网络地址和广播地址
        console.print(f"[bold green]开始扫描网段 {cidr_input}，共 {len(ip_range)} 个IP[/bold green]")

        # 扫描IP网段 (并发处理)
        scan_ips_concurrent(ip_range)

    except ValueError:
        console.print("[bold red]无效的CIDR格式，请重新输入。[/bold red]")
