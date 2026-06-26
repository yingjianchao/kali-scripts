#!/usr/bin/env python3
"""路由器安全审计 - 检测常见漏洞和弱配置"""
import argparse, requests, socket, sys

class RouterAuditor:
    def __init__(self, target, port=80):
        self.target = target
        self.port = port
        self.base = f"http://{target}:{port}"
        self.findings = []

    def check_ports(self):
        """检查常见端口"""
        print("🔍 检查开放端口...")
        dangerous = {21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
                     8080: "HTTP-Proxy", 22: "SSH", 3389: "RDP"}
        for port, name in dangerous.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((self.target, port)) == 0:
                    level = "⚠️ 高危" if port in (21, 23, 3389) else "ℹ️ 信息"
                    self.findings.append({"level": level, "msg": f"端口 {port} ({name}) 开放"})
                    print(f"  {level}: {port}/{name} 开放")
                s.close()
            except: pass

    def check_http_headers(self):
        """检查 HTTP 安全头"""
        print("\n🔍 检查 HTTP 响应头...")
        try:
            r = requests.get(self.base, timeout=5)
            headers = r.headers
            server = headers.get("Server", "未知")
            print(f"  Server: {server}")

            # 检查安全头
            security_headers = {
                "X-Frame-Options": "防点击劫持",
                "X-Content-Type-Options": "防MIME嗅探",
                "X-XSS-Protection": "XSS防护",
                "Content-Security-Policy": "CSP",
                "Strict-Transport-Security": "HSTS"
            }
            for header, desc in security_headers.items():
                if header not in headers:
                    self.findings.append({"level": "⚠️ 中危", "msg": f"缺少 {header} ({desc})"})
                    print(f"  ⚠️ 缺少: {header}")
                else:
                    print(f"  ✅ 存在: {header}")
        except Exception as e:
            print(f"  ❌ 连接失败: {e}")

    def check_default_creds(self):
        """检测默认凭据"""
        print("\n🔍 检测默认凭据...")
        defaults = [
            ("admin", "admin"), ("admin", ""), ("admin", "password"),
            ("root", "root"), ("root", ""), ("admin", "1234"),
            ("admin", "admin123"), ("user", "user")
        ]
        for user, pwd in defaults:
            try:
                r = requests.post(f"{self.base}/cgi-bin/luci/api/auth",
                                json={"method": "login", "params": {"username": user, "password": pwd}},
                                timeout=3)
                data = r.json()
                if data.get("data", {}).get("sid"):
                    self.findings.append({"level": "🔴 严重", "msg": f"默认凭据: {user}/{pwd}"})
                    print(f"  🔴 发现默认凭据: {user}/{pwd}")
                    return
            except: pass
        print("  ✅ 未发现常见默认凭据")

    def check_info_disclosure(self):
        """信息泄露检查"""
        print("\n🔍 检查信息泄露...")
        paths = ["/cgi-bin/luci/", "/etc/shadow", "/etc/passwd",
                 "/tmp/", "/var/log/", "/.env", "/backup"]
        for path in paths:
            try:
                r = requests.get(f"{self.base}{path}", timeout=3)
                if r.status_code == 200 and len(r.text) > 100:
                    self.findings.append({"level": "⚠️ 中危", "msg": f"可访问: {path}"})
                    print(f"  ⚠️ 可访问: {path}")
            except: pass

    def run_all(self):
        """运行所有检查"""
        print(f"🔐 路由器安全审计: {self.target}:{self.port}\n")
        self.check_ports()
        self.check_http_headers()
        self.check_default_creds()
        self.check_info_disclosure()

        print(f"\n{'='*50}")
        print(f"📊 审计结果: {len(self.findings)} 个发现")
        critical = sum(1 for f in self.findings if "严重" in f["level"])
        high = sum(1 for f in self.findings if "高危" in f["level"])
        medium = sum(1 for f in self.findings if "中危" in f["level"])
        print(f"  🔴 严重: {critical}  ⚠️ 高危: {high}  ⚠️ 中危: {medium}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="路由器安全审计")
    p.add_argument("--target", required=True, help="目标 IP")
    p.add_argument("--port", type=int, default=80, help="HTTP 端口")
    args = p.parse_args()
    auditor = RouterAuditor(args.target, args.port)
    auditor.run_all()
