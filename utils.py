import logging
import datetime as _dt
from typing import Dict, List, Callable, Optional
import requests
from models import VulnItem

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_crawler.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------- HTTP 会话 ----------------
_session = requests.Session()
_session.headers.update({
    "User-Agent": "Mozilla/5.0 vuln-crawler/1.1 (+https://example.com)",
    "Accept": "application/json, text/plain, */*",
    "Connection": "close",
})

# ---------------- 去重合并 ----------------
Fetcher = Callable[[str], List[VulnItem]]

def fetch_all(target_date: str, fetchers: List[Fetcher]) -> List[VulnItem]:
    seen: Dict[str, VulnItem] = {}
    for fn in fetchers:
        try:
            items = fn(target_date)
            logger.info(f"[{fn.__name__}] {len(items)} item(s)")
        except Exception as e:
            logger.error(f"[{fn.__name__}] ERROR → {e}")
            continue

        for it in items:
            key = it.cve or f"{it.name}_{it.date}"
            seen.setdefault(key, it)

    return list(seen.values())

# ---------------- 代理设置 ----------------
def _normalize(url: Optional[str], default_scheme: str) -> Optional[str]:
    """
    若 url 为 '127.0.0.1:7890' → 自动补 'http://127.0.0.1:7890'
    若已带 scheme（http://、https://、socks5://…）则原样返回
    """
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        url = f"{default_scheme}://{url}"
    return url

def set_proxy(http_url: Optional[str] = None,
              https_url: Optional[str] = None) -> None:
    """
    运行时更新代理:
      http_url  —— 形如 '127.0.0.1:7890' 或完整 'http://...' / 'socks5://...'
      https_url —— 同上
    传 None / '' 表示清空对应协议代理
    """
    http_url  = _normalize(http_url,  "http")
    https_url = _normalize(https_url, "http")   # HTTPS 代理常用 http CONNECT 隧道

    proxies = _session.proxies.copy()
    if http_url:
        proxies['http'] = http_url
    else:
        proxies.pop('http', None)

    if https_url:
        proxies['https'] = https_url
    else:
        proxies.pop('https', None)

    _session.proxies = proxies

# ---------------- 小工具 ----------------
def today() -> str:
    return _dt.date.today().isoformat()

# ---------------- Markdown 格式化 ----------------
def format_markdown(vuln: VulnItem, index: int, poc_urls: List[str] = None) -> str:
    """将漏洞信息格式化为Markdown字符串"""
    md = [f"### {index}. {vuln.name}"]
    if vuln.cve:
        md.append(f"- **CVE ID**: [{vuln.cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve})")
    md.append(f"- **发布日期**: {vuln.date}")
    md.append(f"- **严重程度**: {vuln.severity}")
    md.append(f"- **来源**: {vuln.source}")
    md.append(f"- **漏洞描述**\n{vuln.description}")
    
    # 添加Poc/EXP信息
    if poc_urls and len(poc_urls) > 0:
        md.append("- **Poc/EXP**")
        for url in poc_urls:
            md.append(f"  - [{url}]({url})")
    
    if vuln.reference:
        md.append("- **参考链接")
        # 确保reference始终是列表
        references = vuln.reference if isinstance(vuln.reference, list) else [vuln.reference]
        for ref in references:
            if isinstance(ref, str) and ref.startswith(('http://', 'https://')):
                md.append(f"- [{ref}]({ref})")
            elif isinstance(ref, str):
                md.append(f"- {ref}")
    return '\n'.join(md)
