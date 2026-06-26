#!/usr/bin/env python3
"""
WiFi 分析器 - WiFi Analyzer
功能：扫描附近WiFi网络，显示信号强度、加密方式、信道等信息
用法：sudo python3 wifi_analyzer.py -i wlan0

⚠️ 仅用于合法的无线网络安全评估
需要：Linux系统 + 无线网卡 + iw/iwlist工具
"""

import argparse
import subprocess
import re
import sys
import time
from datetime import datetime


def check_root():
    """检查是否以root权限运行"""
    import os
    if os.geteuid() != 0:
        print("[错误] WiFi扫描需要root权限，请使用 sudo 运行")
        sys.exit(1)


def check_interface(interface: str) -> bool:
    """检查无线网卡是否存在"""
    try:
        result = subprocess.run(
            ['iw', 'dev', interface, 'info'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print(f"[+] 无线网卡 {interface} 已就绪")
            return True
    except FileNotFoundError:
        pass

    # 备用检查：iwconfig
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True, text=True, timeout=5
        )
        if 'no wireless extensions' not in result.stdout.lower() and result.returncode == 0:
            print(f"[+] 无线网卡 {interface} 已就绪")
            return True
    except FileNotFoundError:
        pass

    print(f"[错误] 无线网卡 {interface} 不存在或不可用")
    return False


def list_interfaces() -> list[str]:
    """列出所有无线网卡"""
    interfaces = []
    try:
        result = subprocess.run(
            ['iw', 'dev'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            match = re.search(r'Interface\s+(\w+)', line)
            if match:
                interfaces.append(match.group(1))
    except FileNotFoundError:
        # 备用方案：通过 /sys/class/net 查找
        try:
            result = subprocess.run(
                ['ls', '/sys/class/net/'],
                capture_output=True, text=True, timeout=5
            )
            for iface in result.stdout.strip().split():
                try:
                    check = subprocess.run(
                        ['iwconfig', iface],
                        capture_output=True, text=True, timeout=3
                    )
                    if 'IEEE 802.11' in check.stdout:
                        interfaces.append(iface)
                except:
                    pass
        except:
            pass
    return interfaces


def enable_monitor_mode(interface: str) -> str:
    """
    启用监听模式（可选）
    监听模式可以捕获更多WiFi信息
    """
    print(f"[*] 尝试将 {interface} 设为监听模式...")
    try:
        # 先尝试用 airmon-ng
        subprocess.run(
            ['airmon-ng', 'check', 'kill'],
            capture_output=True, timeout=10
        )
        result = subprocess.run(
            ['airmon-ng', 'start', interface],
            capture_output=True, text=True, timeout=10
        )
        # 查找 monitor 接口名
        monitor_match = re.search(r'(mon\d+|wlan\d+mon)', result.stdout)
        if monitor_match:
            mon_iface = monitor_match.group(1)
            print(f"[+] 监听模式已启用: {mon_iface}")
            return mon_iface
    except FileNotFoundError:
        pass

    # 备用方案：ip + iw
    try:
        subprocess.run(
            ['ip', 'link', 'set', interface, 'down'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['iw', 'dev', interface, 'set', 'type', 'monitor'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['ip', 'link', 'set', interface, 'up'],
            capture_output=True, timeout=5
        )
        print(f"[+] 监听模式已启用: {interface}")
        return interface
    except Exception as e:
        print(f"[!] 启用监听模式失败: {e}")
        print("[*] 将使用普通模式扫描（信息可能不完整）")
        return interface


def disable_monitor_mode(interface: str, original_interface: str):
    """恢复管理模式"""
    if interface != original_interface:
        try:
            subprocess.run(
                ['airmon-ng', 'stop', interface],
                capture_output=True, timeout=10
            )
        except:
            pass

    try:
        subprocess.run(
            ['ip', 'link', 'set', original_interface, 'down'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['iw', 'dev', original_interface, 'set', 'type', 'managed'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['ip', 'link', 'set', original_interface, 'up'],
            capture_output=True, timeout=5
        )
        print(f"[+] 已恢复管理模式: {original_interface}")
    except:
        pass


def scan_with_iw(interface: str, scan_time: int = 10) -> list[dict]:
    """
    使用 iw 扫描WiFi网络
    """
    networks = []
    print(f"[*] 使用 iw 扫描附近WiFi网络...")

    try:
        # 触发扫描
        subprocess.run(
            ['iw', 'dev', interface, 'scan', 'trigger'],
            capture_output=True, timeout=10
        )
        time.sleep(2)

        # 获取扫描结果
        result = subprocess.run(
            ['iw', 'dev', interface, 'scan'],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            print(f"[!] iw扫描失败: {result.stderr.strip()}")
            return networks

        # 解析输出
        current = {}
        for line in result.stdout.split('\n'):
            line = line.strip()

            # BSS (MAC地址)
            bss_match = re.match(r'BSS ([0-9a-f:]+)', line)
            if bss_match:
                if current and 'bssid' in current:
                    networks.append(current)
                current = {'bssid': bss_match.group(1), 'channel': 0, 'signal': 0,
                          'encryption': '未知', 'wps': False}
                continue

            # SSID
            ssid_match = re.match(r'SSID:\s*(.*)', line)
            if ssid_match:
                current['ssid'] = ssid_match.group(1) or '(隐藏SSID)'
                continue

            # 信号强度
            signal_match = re.match(r'signal:\s*([-\d.]+)\s*dBm', line)
            if signal_match:
                current['signal'] = float(signal_match.group(1))
                continue

            # 频率和信道
            freq_match = re.match(r'freq:\s*(\d+)', line)
            if freq_match:
                freq = int(freq_match.group(1))
                # 2.4GHz 信道计算
                if 2412 <= freq <= 2484:
                    current['channel'] = (freq - 2407) // 5
                    current['band'] = '2.4GHz'
                # 5GHz 信道计算
                elif 5170 <= freq <= 5825:
                    current['channel'] = (freq - 5000) // 5
                    current['band'] = '5GHz'
                continue

            # 加密方式
            if 'WPA3' in line or 'SAE' in line:
                current['encryption'] = 'WPA3'
            elif 'WPA2' in line or 'RSN' in line:
                current['encryption'] = 'WPA2'
            elif 'WPA' in line:
                current['encryption'] = 'WPA'
            elif 'WEP' in line:
                current['encryption'] = 'WEP'
            elif 'open' in line.lower() or 'capability: 0x0421' in line:
                current['encryption'] = '开放(无加密)'

            # WPS
            if 'WPS' in line:
                current['wps'] = True

        # 别忘了最后一个
        if current and 'bssid' in current:
            networks.append(current)

    except FileNotFoundError:
        print("[错误] 系统未安装 iw 工具")
    except Exception as e:
        print(f"[错误] 扫描失败: {e}")

    return networks


def scan_with_iwlist(interface: str) -> list[dict]:
    """
    备用方案：使用 iwlist 扫描
    """
    networks = []
    print(f"[*] 使用 iwlist 扫描附近WiFi网络...")

    try:
        result = subprocess.run(
            ['iwlist', interface, 'scan'],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            print(f"[!] iwlist扫描失败")
            return networks

        # 解析 iwlist 输出
        current = {}
        for line in result.stdout.split('\n'):
            line = line.strip()

            cell_match = re.search(r'Cell \d+.*Address: ([0-9A-Fa-f:]+)', line)
            if cell_match:
                if current:
                    networks.append(current)
                current = {
                    'bssid': cell_match.group(1),
                    'ssid': '未知', 'channel': 0, 'signal': 0,
                    'encryption': '未知', 'wps': False, 'band': '未知'
                }
                continue

            essid_match = re.search(r'ESSID:"(.*)"', line)
            if essid_match:
                current['ssid'] = essid_match.group(1) or '(隐藏SSID)'
                continue

            channel_match = re.search(r'Channel:(\d+)', line)
            if channel_match:
                ch = int(channel_match.group(1))
                current['channel'] = ch
                current['band'] = '2.4GHz' if ch <= 14 else '5GHz'
                continue

            signal_match = re.search(r'Signal level[=:]([-\d]+)', line)
            if signal_match:
                current['signal'] = int(signal_match.group(1))
                continue

            if 'WPA2' in line or 'RSN' in line:
                current['encryption'] = 'WPA2'
            elif 'WPA' in line:
                current['encryption'] = 'WPA'
            elif 'WEP' in line:
                current['encryption'] = 'WEP'
            elif 'Encryption key:off' in line:
                current['encryption'] = '开放(无加密)'

        if current:
            networks.append(current)

    except FileNotFoundError:
        print("[错误] 系统未安装 iwlist 工具")
    except Exception as e:
        print(f"[错误] 扫描失败: {e}")

    return networks


def get_signal_quality(dbm: float) -> str:
    """将信号强度转换为质量等级"""
    if dbm >= -30:
        return '极好 ★★★★★'
    elif dbm >= -50:
        return '很好 ★★★★☆'
    elif dbm >= -60:
        return '良好 ★★★☆☆'
    elif dbm >= -70:
        return '一般 ★★☆☆☆'
    elif dbm >= -80:
        return '较差 ★☆☆☆☆'
    else:
        return '极差 ☆☆☆☆☆'


def analyze_security(network: dict) -> str:
    """分析WiFi网络安全风险"""
    risks = []
    enc = network.get('encryption', '未知')

    if enc == '开放(无加密)':
        risks.append('⚠️ 无加密，数据明文传输')
    elif enc == 'WEP':
        risks.append('⚠️ WEP加密已被破解，极度不安全')
    elif enc == 'WPA':
        risks.append('⚠️ WPA1存在已知漏洞')
    elif enc == 'WPA3':
        risks.append('✅ WPA3安全性最好')

    if network.get('wps'):
        risks.append('⚠️ 启用了WPS，可能被暴力破解')

    if network.get('signal', 0) > -30:
        risks.append('ℹ️ 信号极强，可能距离很近')

    return '; '.join(risks) if risks else '✅ 安全配置良好'


def display_results(networks: list[dict]):
    """以表格形式显示扫描结果"""
    if not networks:
        print("\n[!] 未发现任何WiFi网络")
        return

    # 按信号强度排序
    networks.sort(key=lambda x: x.get('signal', -999), reverse=True)

    print(f"\n{'='*100}")
    print(f"WiFi网络扫描结果 - 共发现 {len(networks)} 个网络")
    print(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*100}\n")

    print(f"{'序号':<4} {'SSID':<24} {'BSSID':<18} {'信道':<6} {'频段':<8} {'信号(dBm)':<12} {'加密':<16} {'安全评估'}")
    print(f"{'-'*4} {'-'*24} {'-'*18} {'-'*6} {'-'*8} {'-'*12} {'-'*16} {'-'*30}")

    for i, net in enumerate(networks, 1):
        ssid = net.get('ssid', '未知')[:23]
        bssid = net.get('bssid', 'N/A')
        channel = str(net.get('channel', '?'))
        band = net.get('band', '?')
        signal = net.get('signal', 0)
        encryption = net.get('encryption', '未知')
        quality = get_signal_quality(signal)
        security = analyze_security(net)

        print(f"{i:<4} {ssid:<24} {bssid:<18} {channel:<6} {band:<8} {signal:<12} {encryption:<16} {security}")

    # 安全建议
    print(f"\n{'='*100}")
    print("安全建议:")
    print("  1. 避免连接使用 WEP 或无加密的网络")
    print("  2. 首选 WPA3/WPA2 加密的网络")
    print("  3. 关闭路由器的 WPS 功能")
    print("  4. 使用强密码（12位以上，包含大小写字母、数字和特殊字符）")
    print(f"{'='*100}")


# ==================== 主程序 ====================

def main():
    parser = argparse.ArgumentParser(
        description='WiFi网络分析器 - 扫描附近无线网络信息',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  sudo python3 wifi_analyzer.py                      # 自动选择无线网卡
  sudo python3 wifi_analyzer.py -i wlan0             # 指定无线网卡
  sudo python3 wifi_analyzer.py --list               # 列出所有无线网卡
  sudo python3 wifi_analyzer.py -i wlan0 --monitor   # 使用监听模式

⚠️ 仅用于合法的无线网络安全评估
        """
    )
    parser.add_argument('-i', '--interface', default=None, help='无线网卡接口名')
    parser.add_argument('--list', action='store_true', help='列出所有无线网卡')
    parser.add_argument('--monitor', action='store_true', help='启用监听模式')
    parser.add_argument('--method', choices=['iw', 'iwlist'], default='iw', help='扫描工具')

    args = parser.parse_args()

    print("\n" + "="*60)
    print("📡 WiFi 网络分析器")
    print("⚠️  仅用于合法的无线网络安全评估")
    print("="*60)

    # 列出网卡
    if args.list:
        interfaces = list_interfaces()
        if interfaces:
            print(f"\n发现的无线网卡:")
            for iface in interfaces:
                print(f"  - {iface}")
        else:
            print("\n未发现无线网卡")
        return

    # 检查root权限
    check_root()

    # 确定网卡
    interface = args.interface
    if not interface:
        interfaces = list_interfaces()
        if not interfaces:
            print("[错误] 未发现无线网卡，请使用 -i 参数指定")
            sys.exit(1)
        interface = interfaces[0]
        print(f"[*] 自动选择网卡: {interface}")

    if not check_interface(interface):
        sys.exit(1)

    # 启用监听模式（可选）
    original_iface = interface
    if args.monitor:
        interface = enable_monitor_mode(interface)

    try:
        # 执行扫描
        if args.method == 'iw':
            networks = scan_with_iw(interface)
            if not networks:
                print("[*] iw 未发现网络，尝试 iwlist...")
                networks = scan_with_iwlist(interface)
        else:
            networks = scan_with_iwlist(interface)
            if not networks:
                print("[*] iwlist 未发现网络，尝试 iw...")
                networks = scan_with_iw(interface)

        # 显示结果
        display_results(networks)

    finally:
        # 恢复网卡模式
        if args.monitor:
            disable_monitor_mode(interface, original_iface)


if __name__ == '__main__':
    main()
