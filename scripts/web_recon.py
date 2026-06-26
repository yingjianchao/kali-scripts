#!/usr/bin/env python3
"""Web 信息收集工具 - 子域名、目录扫描、技术识别"""
import argparse, requests, socket, sys, time
from concurrent.futures import ThreadPoolExecutor

def subdomain_enum(domain, wordlist=None):
    """子域名枚举"""
    if not wordlist:
        subs = ["www", "mail", "ftp", "admin", "test", "dev", "api", "blog",
                "shop", "cdn", "img", "static", "app", "m", "mobile", "oa",
                "vpn", "git", "jenkins", "jira", "confluence", "wiki"]
    else:
        with open(wordlist) as f:
            subs = [l.strip() for l in f if l.strip()]

    found = []
    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except:
            return None

    print(f"🔍 枚举子域名 ({len(subs)} 个)...")
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(check_sub, subs))

    found = [r for r in results if r]
    for f in found:
        print(f"  ✅ {f[\'subdomain\']:30} → {f[\'ip\']}")
    print(f"\n📊 发现 {len(found)} 个子域名")
    return found

def dir_brute(target_url, wordlist=None):
    """目录扫描"""
    if not wordlist:
        dirs = ["admin", "login", "wp-admin", "phpmyadmin", "backup", "test",
                "api", "docs", "swagger", ".env", ".git", "robots.txt",
                "sitemap.xml", "crossdomain.xml", "server-status", "console"]
    else:
        with open(wordlist) as f:
            dirs = [l.strip() for l in f if l.strip()]

    found = []
    print(f"🔍 扫描目录 ({len(dirs)} 个)...")
    for d in dirs:
        try:
            url = f"{target_url.rstrip('/')}/{d}"
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code not in (404, 403):
                size = len(r.text)
                found.append({"path": d, "status": r.status_code, "size": size})
                print(f"  ✅ /{d:20} {r.status_code:4} {size:8} bytes")
        except: pass
    return found

def tech_detect(target_url):
    """技术栈识别"""
    print(f"\n🔍 识别技术栈...")
    try:
        r = requests.get(target_url, timeout=10)
        headers = r.headers
        body = r.text[:5000]

        techs = []
        # 服务器
        if "Server" in headers:
            techs.append(f"服务器: {headers[\'Server\']}")

        # 框架检测
        checks = {
            "X-Powered-By": lambda v: f"运行环境: {v}",
            "X-Generator": lambda v: f"CMS: {v}",
        }
        for header, fmt in checks.items():
            if header in headers:
                techs.append(fmt(headers[header]))

        # HTML 特征
        patterns = {
            "wp-content": "WordPress",
            "Joomla": "Joomla",
            "Drupal": "Drupal",
            "ThinkPHP": "ThinkPHP",
            "Laravel": "Laravel",
            "Django": "Django",
            "Flask": "Flask",
            "Express": "Node.js/Express",
            "Vue.js": "Vue.js",
            "React": "React",
            "Angular": "Angular",
            "jQuery": "jQuery",
            "Bootstrap": "Bootstrap",
        }
        for pattern, name in patterns.items():
            if pattern.lower() in body.lower():
                techs.append(f"前端/框架: {name}")

        for t in techs:
            print(f"  🏷️  {t}")
        return techs
    except Exception as e:
        print(f"  ❌ 连接失败: {e}")
        return []

def grab_robots(target_url):
    """获取 robots.txt"""
    print(f"\n🔍 检查 robots.txt...")
    try:
        r = requests.get(f"{target_url.rstrip('/')}/robots.txt", timeout=5)
        if r.status_code == 200:
            print(f"  ✅ 找到 robots.txt:")
            for line in r.text.split("\n")[:20]:
                if line.strip():
                    print(f"    {line}")
            return r.text
        else:
            print(f"  ❌ 不存在 (HTTP {r.status_code})")
    except: pass
    return None


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Web 信息收集")
    p.add_argument("--target", required=True, help="目标域名或 URL")
    p.add_argument("--subdomains", action="store_true", help="子域名枚举")
    p.add_argument("--dirs", action="store_true", help="目录扫描")
    p.add_argument("--tech", action="store_true", help="技术识别")
    p.add_argument("--all", action="store_true", help="全部执行")
    args = p.parse_args()

    target = args.target if args.target.startswith("http") else f"http://{args.target}"
    domain = target.split("//")[1].split("/")[0]

    if args.all or args.subdomains:
        subdomain_enum(domain)
    if args.all or args.dirs:
        dir_brute(target)
    if args.all or args.tech:
        tech_detect(target)
    if args.all:
        grab_robots(target)
    if not any([args.subdomains, args.dirs, args.tech, args.all]):
        p.print_help()
