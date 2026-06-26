#!/usr/bin/env python3
"""密码强度审计 - 检测弱密码、生成字典"""
import argparse, hashlib, re, sys

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwerty123", "password1", "admin", "admin123",
    "root", "toor", "pass", "test", "guest", "info", "mysql",
    "Chaos8733", "Qwe123123"
]

def check_strength(password):
    """评估密码强度"""
    score = 0
    feedback = []

    if len(password) >= 8: score += 1
    else: feedback.append("长度不足8位")
    if len(password) >= 12: score += 1

    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("缺少小写字母")
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("缺少大写字母")
    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("缺少数字")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
    else: feedback.append("缺少特殊字符")

    if password.lower() in [p.lower() for p in COMMON_PASSWORDS]:
        score = 0
        feedback = ["这是常见密码！"]

    levels = {0: "🔴 极弱", 1: "🔴 弱", 2: "⚠️ 较弱", 3: "⚠️ 一般", 4: "✅ 较强", 5: "✅ 强", 6: "💪 极强"}
    return levels.get(score, "未知"), score, feedback

def generate_wordlist(base_words, output="custom_wordlist.txt"):
    """基于关键词生成密码字典"""
    variants = set()
    suffixes = ["", "123", "!", "@", "#", "123!", "666", "888", "000", "2024", "2025", "2026"]

    for word in base_words:
        variants.add(word)
        variants.add(word.lower())
        variants.add(word.upper())
        variants.add(word.capitalize())
        for suffix in suffixes:
            variants.add(word + suffix)
            variants.add(word.capitalize() + suffix)
        # l33t speak
        leet = word.replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0")
        variants.add(leet)

    with open(output, "w") as f:
        for v in sorted(variants):
            f.write(v + "\n")
    print(f"📝 生成 {len(variants)} 个密码变体 → {output}")

def hash_lookup(hash_value, hash_type="md5"):
    """在常见密码中查找哈希"""
    for pwd in COMMON_PASSWORDS:
        h = getattr(hashlib, hash_type)(pwd.encode()).hexdigest()
        if h == hash_value.lower():
            return pwd
    return None


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="密码强度审计")
    sub = p.add_subparsers(dest="cmd")

    s1 = sub.add_parser("check", help="检查密码强度")
    s1.add_argument("password", help="要检查的密码")

    s2 = sub.add_parser("gen", help="生成密码字典")
    s2.add_argument("words", nargs="+", help="基础关键词")
    s2.add_argument("-o", "--output", default="custom_wordlist.txt")

    s3 = sub.add_parser("crack", help="哈希反查")
    s3.add_argument("hash", help="哈希值")
    s3.add_argument("--type", default="md5", choices=["md5", "sha1", "sha256"])

    args = p.parse_args()
    if args.cmd == "check":
        level, score, feedback = check_strength(args.password)
        print(f"密码强度: {level} ({score}/6)")
        for f in feedback:
            print(f"  • {f}")
    elif args.cmd == "gen":
        generate_wordlist(args.words, args.output)
    elif args.cmd == "crack":
        result = hash_lookup(args.hash, args.type)
        if result:
            print(f"✅ 找到: {result}")
        else:
            print("❌ 未在常见密码中找到")
    else:
        p.print_help()
