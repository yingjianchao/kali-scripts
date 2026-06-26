#!/usr/bin/env python3
"""网络扫描器 - ARP扫描、端口扫描、服务发现"""
import argparse, socket, struct, sys, time
from concurrent.futures import ThreadPoolExecutor

def arp_scan(network, interface="eth0"):
    """ARP 扫描发现局域网活跃主机"""
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), iface=interface, timeout=3, verbose=0)
        hosts = []
        for _, rcv in ans:
            hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
        return hosts
    except ImportError:
        # fallback: ping sweep
        print("scapy 未安装，使用 ping 扫描")
        return ping_sweep(network)

def ping_sweep(network):
    """Ping 扫描（ARP 的 fallback）"""
    import subprocess, ipaddress
    hosts = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        ip_str = str(ip)
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str],
                              capture_output=True, timeout=2)
        if result.returncode == 0:
            hosts.append({"ip": ip_str, "mac": "未知"})
            print(f"  ✅ {ip_str} 存活")
    return hosts

def port_scan(host, ports="1-1024", threads=100):
    """TCP 端口扫描"""
    open_ports = []
    port_range = parse_ports(ports)

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                return port
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(pool.map(check_port, port_range))

    return sorted([p for p in results if p])

def parse_ports(ports_str):
    """解析端口范围字符串"""
    ports = []
    for part in ports_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end)+1))
        else:
            ports.append(int(part))
    return ports

def service_detect(host, port):
    """简单服务识别"""
    banners = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
               80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
               993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
               8443: "HTTPS-Alt", 27017: "MongoDB"}
    if port in banners:
        return banners[port]

    # 尝试抓 banner
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner[:50] if banner else "未知"
    except:
        return "未知"


def main():
    p = argparse.ArgumentParser(description="网络扫描器")
    p.add_argument("--scan", help="扫描网段 (如 192.168.1.0/24)")
    p.add_argument("--target", help="扫描目标 IP")
    p.add_argument("--ports", default="1-1024", help="端口范围")
    p.add_argument("--threads", type=int, default=100)
    p.add_argument("--interface", default="eth0")
    p.add_argument("--service", action="store_true", help="识别服务")
    args = p.parse_args()

    if args.scan:
        print(f"🔍 ARP 扫描 {args.scan} ...")
        hosts = arp_scan(args.scan, args.interface)
        print(f"\n📊 发现 {len(hosts)} 台主机:")
        for h in hosts:
            print(f"  {h[\'ip\']:16} {h[\'mac\']}")

    if args.target:
        print(f"🔍 端口扫描 {args.target} (范围: {args.ports}) ...")
        ports = port_scan(args.target, args.ports, args.threads)
        print(f"\n📊 开放端口 ({len(ports)} 个):")
        for port in ports:
            svc = service_detect(args.target, port) if args.service else ""
            print(f"  {port:6} {'open':8} {svc}")


if __name__ == "__main__":
    main()
