#!/bin/bash
# 一键部署 Xray Reality 节点，同时生成 Clash 和 V2Ray 订阅链接
# 系统要求：Linux 发行版
# Ubuntu: 20.04, 22.04, 24.04 及更高版本（推荐）
# Debian: 12 及更高版本

set -euo pipefail

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 配置变量
PROXY_PORT="443"
SUB_PORT="8443"
PROXY_GROUP_NAME="Proxy(Tokyo-AWS)"
ENABLE_BBR="true"
GENERATE_V2RAY_SUB="false"
BEST_SNI="www.bing.com"
# 备选（按需手动切换）:
# BEST_SNI="www.apple.com"
# BEST_SNI="www.microsoft.com"
# BEST_SNI="www.amazon.com"
# BEST_SNI="www.python.org"

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}请使用 root 权限运行此脚本${NC}"
    exit 1
fi

if [[ $# -gt 0 ]]; then
    echo -e "${RED}此脚本不接受命令行参数${NC}"
    exit 1
fi

# 代理端口固定为 443，订阅端口固定为 8443
# 生成UUID
UUID=$(cat /proc/sys/kernel/random/uuid)

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}      Xray Reality 一键安装脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${GREEN}[1/7] 安装依赖...${NC}"
apt update -y
apt install -y curl openssl nginx bc qrencode

if [[ "${ENABLE_BBR}" == "true" ]]; then
    echo -e "${GREEN}[2/7] 启用 BBR...${NC}"
    cat > /etc/sysctl.d/99-bbr.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    if sysctl --system >/dev/null 2>&1; then
        echo "BBR status: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    else
        echo -e "${YELLOW}BBR 启用失败，继续安装流程${NC}"
    fi
fi

echo -e "${GREEN}[3/7] 安装 Xray...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo -e "${GREEN}[4/7] 生成 Reality 密钥对 & 使用固定 SNI...${NC}"
echo -e "${YELLOW}固定 SNI: ${BEST_SNI}${NC}"

# 生成密钥
KEYS=$(/usr/local/bin/xray x25519)
echo "x25519 原始输出:"
echo "$KEYS"
echo "---"

# 直接用 sed 提取 (兼容不同 xray x25519 输出格式)
PRIVATE_KEY=$(echo "$KEYS" | sed -n 's/.*PrivateKey: *\([^ ]*\).*/\1/p' | head -1)
PUBLIC_KEY=$(echo "$KEYS" | sed -n 's/.*PublicKey: *\([^ ]*\).*/\1/p' | head -1)

# 兼容部分版本使用 Password 表示对端公钥
if [[ -z "$PUBLIC_KEY" ]]; then
    PUBLIC_KEY=$(echo "$KEYS" | sed -n 's/.*Password: *\([^ ]*\).*/\1/p' | head -1)
fi

# 如果上面没提取到，尝试旧格式 (Private key/Public key: xxx)
if [[ -z "$PRIVATE_KEY" ]]; then
    PRIVATE_KEY=$(echo "$KEYS" | sed -n 's/.*Private key: *\([^ ]*\).*/\1/p' | head -1)
fi
if [[ -z "$PUBLIC_KEY" ]]; then
    PUBLIC_KEY=$(echo "$KEYS" | sed -n 's/.*Public key: *\([^ ]*\).*/\1/p' | head -1)
fi

SHORT_ID=$(openssl rand -hex 8)

# 验证密钥
if [[ -z "$PRIVATE_KEY" ]] || [[ -z "$PUBLIC_KEY" ]]; then
    echo -e "${RED}错误: 密钥提取失败。原始输出如下:${NC}"
    echo "$KEYS"
    exit 1
fi

echo -e "${GREEN}[5/7] 写入 Xray 配置...${NC}"
cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${PROXY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "${BEST_SNI}:443",
          "serverNames": ["${BEST_SNI}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

echo -e "${GREEN}[6/7] 启动 Xray 服务...${NC}"
systemctl restart xray
systemctl enable xray

# 获取服务器IP
SERVER_IP=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || curl -s ifconfig.me)
SUB_HOST="${SERVER_IP}"
SUB_SCHEME="http"

echo -e "${GREEN}[7/7] 生成订阅文件...${NC}"

# 创建订阅目录
SUBSCRIBE_DIR="/var/www/subscribe"
mkdir -p "${SUBSCRIBE_DIR}"
SUBSCRIBE_TOKEN=$(openssl rand -hex 16)

# ============================================
# V2Ray 订阅 (Base64 编码的 VLESS 链接)
# ============================================
if [[ "${GENERATE_V2RAY_SUB}" == "true" ]]; then
    VLESS_LINK="vless://${UUID}@${SERVER_IP}:${PROXY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${BEST_SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    echo -n "${VLESS_LINK}" | base64 | tr -d '\n' > "${SUBSCRIBE_DIR}/${SUBSCRIBE_TOKEN}.txt"
    # 生成 VLESS 二维码图片 (网页端查看)
    qrencode -o "${SUBSCRIBE_DIR}/${SUBSCRIBE_TOKEN}_vless.png" "${VLESS_LINK}"
fi

# ============================================
# Clash Meta 订阅 (YAML 格式)
# ============================================
CLASH_SUB_URL="${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.yaml"
cat > "${SUBSCRIBE_DIR}/${SUBSCRIBE_TOKEN}.yaml" << EOF
mixed-port: 7890
allow-lan: true
mode: rule
log-level: warning
external-controller: 127.0.0.1:9090

geo-auto-update: true
geosite-auto-update: true

dns:
  enable: true
  enhanced-mode: fake-ip
  ipv6: false

  nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://dns.alidns.com/dns-query

  fallback:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
    - tls://1.1.1.1:853

  fallback-filter:
    geoip: true
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
      - 127.0.0.1/32
    domain:
      - +.google.com
      - +.facebook.com
      - +.youtube.com
      - +.xn--ngstr-lra8j.com
      - +.google.cn
      - +.googleapis.cn
      - +.gvt1.com

  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '*.home'
    - router.asus.com
    - '*.miwifi.com'

    - '*.apple.com'
    - mesu.apple.com
    - api.push.apple.com
    - time.apple.com
    - time-ios.apple.com

    - +.stun.*
    - '*.ntp.org'

proxies:
  - name: Reality-${SERVER_IP}
    type: vless
    server: ${SERVER_IP}
    port: ${PROXY_PORT}
    uuid: ${UUID}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${BEST_SNI}
    reality-opts:
      public-key: ${PUBLIC_KEY}
      short-id: ${SHORT_ID}
    client-fingerprint: chrome

proxy-groups:
  - name: ${PROXY_GROUP_NAME}
    type: select
    proxies:
      - Reality-${SERVER_IP}
      - DIRECT

rule-providers:
  reject:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt
    path: ./ruleset/loyalsoldier/reject.yaml
    interval: 86400
  icloud:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt
    path: ./ruleset/loyalsoldier/icloud.yaml
    interval: 86400
  apple:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt
    path: ./ruleset/loyalsoldier/apple.yaml
    interval: 86400
  google:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt
    path: ./ruleset/loyalsoldier/google.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt
    path: ./ruleset/loyalsoldier/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt
    path: ./ruleset/loyalsoldier/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt
    path: ./ruleset/loyalsoldier/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt
    path: ./ruleset/loyalsoldier/gfw.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt
    path: ./ruleset/loyalsoldier/telegramcidr.yaml
    interval: 86400
  lancidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt
    path: ./ruleset/loyalsoldier/lancidr.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt
    path: ./ruleset/loyalsoldier/cncidr.yaml
    interval: 86400

rules:
  - RULE-SET,reject,REJECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,${PROXY_GROUP_NAME}
  - RULE-SET,proxy,${PROXY_GROUP_NAME}
  - RULE-SET,direct,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,gfw,${PROXY_GROUP_NAME}
  - RULE-SET,telegramcidr,${PROXY_GROUP_NAME},no-resolve
  - RULE-SET,lancidr,DIRECT,no-resolve
  - RULE-SET,cncidr,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,${PROXY_GROUP_NAME}
EOF

# 生成订阅二维码图片
qrencode -o "${SUBSCRIBE_DIR}/${SUBSCRIBE_TOKEN}_clash_sub.png" "${CLASH_SUB_URL}"
if [[ "${GENERATE_V2RAY_SUB}" == "true" ]]; then
    V2RAY_SUB_URL="${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.txt"
    qrencode -o "${SUBSCRIBE_DIR}/${SUBSCRIBE_TOKEN}_v2ray_sub.png" "${V2RAY_SUB_URL}"
fi

# ============================================
# 配置 Nginx
# ============================================
cat > /etc/nginx/sites-available/subscribe << EOF
server {
    listen ${SUB_PORT};
    server_name _;

    location /sub/ {
        alias ${SUBSCRIBE_DIR}/;
        types {
            text/yaml yaml yml;
            text/plain txt;
            image/png png;
        }
        default_type text/plain;
        add_header Access-Control-Allow-Origin *;
    }
}
EOF

ln -sf /etc/nginx/sites-available/subscribe /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t && systemctl restart nginx
systemctl enable nginx

# 开放防火墙端口
if command -v ufw &> /dev/null; then
    ufw allow ${PROXY_PORT}/tcp
    ufw allow ${SUB_PORT}/tcp
fi

# ============================================
# 输出信息
# ============================================
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}           部署完成！${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${YELLOW}【节点信息】${NC}"
echo "服务器IP:    ${SERVER_IP}"
echo "端口:        ${PROXY_PORT}"
echo "UUID:        ${UUID}"
echo "Public Key:  ${PUBLIC_KEY}"
echo "Short ID:    ${SHORT_ID}"
echo "SNI:         ${BEST_SNI}"
echo "Fingerprint: chrome"
echo "Flow:        xtls-rprx-vision"
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${YELLOW}【订阅链接】${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
if [[ "${GENERATE_V2RAY_SUB}" == "true" ]]; then
    echo -e "${YELLOW}V2Ray 订阅 (v2rayN / v2rayNG / Shadowrocket):${NC}"
    echo "链接: ${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.txt"
    echo "二维码: ${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}_v2ray_sub.png"
    qrencode -t ansiutf8 "${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.txt"
    echo ""
fi
echo -e "${YELLOW}Clash 订阅 (Shadowrocket / Clash Meta / Clash Verge / Mihomo):${NC}"
echo "链接: ${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.yaml"
echo "二维码: ${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}_clash_sub.png"
qrencode -t ansiutf8 "${SUB_SCHEME}://${SUB_HOST}:${SUB_PORT}/sub/${SUBSCRIBE_TOKEN}.yaml"
echo ""
echo -e "${YELLOW}【防火墙提示】${NC}"
echo "请在 VPS 本机防火墙和云安全组放行入站 TCP 端口: ${PROXY_PORT}, ${SUB_PORT}"
echo ""
echo -e "${GREEN}============================================${NC}"
