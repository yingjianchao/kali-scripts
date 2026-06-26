# 🔐 Kali-Scripts — 渗透测试工具集

Kali Linux 环境下的安全测试工具集合。

> ⚠️ **免责声明**：本工具仅供**授权的安全测试和教育学习**使用。未经授权对他人系统进行测试是违法行为，后果自负。

## 工具列表

| 脚本 | 功能 |
|------|------|
| `network_scanner.py` | 网络扫描（ARP/端口/服务发现） |
| `router_audit.py` | 路由器安全审计 |
| `wifi_analyzer.py` | WiFi 网络分析 |
| `password_audit.py` | 密码强度审计 |
| `web_recon.py` | Web 信息收集 |

## 使用示例

```bash
# 扫描局域网设备
sudo python scripts/network_scanner.py --scan 192.168.1.0/24

# 审计路由器安全
python scripts/router_audit.py --target 192.168.1.254

# Web 信息收集
python scripts/web_recon.py --target example.com
```

## 环境要求

- Kali Linux 或任何 Linux 发行版
- Python 3.8+
- root 权限（部分功能需要）

## License

MIT
