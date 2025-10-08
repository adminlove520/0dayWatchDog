"""
微步在线高级API实现
-----------------
使用微步在线高级API获取更详细的漏洞信息
支持GUI调用（main.py）和命令行直接查询

API参考: https://x.threatbook.com/v3/apiDocs
"""

import json
import requests
import sys
from typing import Dict, List, Optional, Any
from models import VulnItem
from config_io import load_cfg

# API常量
API_BASE = "https://api.threatbook.cn/v3/vuln"

# 请求头
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "vuln-crawler/1.2",
}

def get_api_key() -> Optional[str]:
    """从配置文件获取微步在线API Key"""
    config = load_cfg()
    return config.get("threatbook_api_key")

def query_vulnerability(vuln_id: str) -> Optional[Dict[str, Any]]:
    """
    查询单个漏洞详情
    
    参数:
        vuln_id: 漏洞ID (可以是CVE编号或微步漏洞编号XVE)
        
    返回:
        漏洞详情数据字典或None（查询失败）
    """
    api_key = get_api_key()
    if not api_key:
        print("[ThreatBook Premium] 未配置API Key")
        return None
    
    params = {
        "apikey": api_key,
        "vuln_id": vuln_id
    }
    
    try:
        response = requests.get(API_BASE, params=params, headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data.get("response_code") == 0:
            return data.get("data")
        else:
            print(f"[ThreatBook Premium] API错误: {data.get('verbose_msg')}")
            return None
    except Exception as e:
        print(f"[ThreatBook Premium] 请求异常: {e}")
        return None

def get_vulnerability_detail(vuln_id: str) -> Optional[VulnItem]:
    """
    获取漏洞详情并转换为VulnItem对象
    
    参数:
        vuln_id: 漏洞ID (可以是CVE编号或微步漏洞编号XVE)
        
    返回:
        VulnItem对象或None（查询失败）
    """
    data = query_vulnerability(vuln_id)
    if not data:
        return None
    
    # 提取基本信息
    name = data.get("name_zh") or data.get("name") or f"漏洞 {vuln_id}"
    date = data.get("publish_time", "")[:10] if data.get("publish_time") else ""
    severity = data.get("severity") or "未知"
    
    # 提取CVE编号
    cve_id = data.get("cve_id") or vuln_id if vuln_id.upper().startswith("CVE-") else vuln_id
    
    # 提取描述信息
    description = data.get("description_zh") or data.get("description") or ""
    
    # 提取CVSS评估
    cvss_info = ""
    if data.get("cvss"):
        cvss = data.get("cvss")
        cvss_info = f"CVSS评分: {cvss.get('score', '未知')}\n"
        cvss_info += f"CVSS向量: {cvss.get('vector', '未知')}\n"
    
    # 提取影响范围
    affected_info = ""
    if data.get("affected"):
        affected = data.get("affected")
        vendors = affected.get("vendors", [])
        affected_info = "影响厂商/产品:\n"
        for vendor in vendors:
            vendor_name = vendor.get("name", "未知厂商")
            products = vendor.get("products", [])
            affected_info += f"- {vendor_name}: "
            affected_info += ", ".join([p.get("name", "未知产品") for p in products]) + "\n"
    
    # 提取POC信息
    poc_urls = []
    if data.get("pocs") and isinstance(data.get("pocs"), list):
        for poc in data.get("pocs"):
            if poc.get("url"):
                poc_urls.append(poc.get("url"))
    
    # 提取修复方案
    solution = ""
    if data.get("solution"):
        solution = f"官方修复方案:\n{data.get('solution')}"
    
    # 合并完整描述
    full_description = f"{description}\n\n"
    if cvss_info:
        full_description += f"{cvss_info}\n"
    if affected_info:
        full_description += f"{affected_info}\n"
    if solution:
        full_description += f"{solution}\n"
    
    # 构建参考链接
    references = []
    if data.get("references") and isinstance(data.get("references"), list):
        references = data.get("references")
    
    # 创建VulnItem对象
    vuln_item = VulnItem(
        name=name,
        cve=cve_id,
        date=date,
        severity=severity,
        tags=data.get("tags", []),
        source="ThreatBook Premium",
        description=full_description.strip(),
        reference=references
    )
    
    # 添加POC URLs作为额外属性
    vuln_item.poc_urls = poc_urls
    
    return vuln_item

def fetch_premium_vuln(vuln_id: str) -> Optional[VulnItem]:
    """
    对外接口：获取高级版微步在线漏洞信息
    
    参数:
        vuln_id: 漏洞ID (可以是CVE编号或微步漏洞编号XVE)
        
    返回:
        VulnItem对象或None（查询失败）
    """
    return get_vulnerability_detail(vuln_id)


def print_vuln_detail(vuln_item: VulnItem) -> None:
    """打印漏洞详情到控制台"""
    if not vuln_item:
        print("未找到漏洞信息")
        return
    
    print("\n" + "="*50)
    print(f"漏洞名称: {vuln_item.name}")
    print(f"漏洞编号: {vuln_item.cve}")
    print(f"发布日期: {vuln_item.date}")
    print(f"危害等级: {vuln_item.severity}")
    print(f"数据来源: {vuln_item.source}")
    print("="*50)
    
    print("\n漏洞描述:")
    print(vuln_item.description)
    
    if hasattr(vuln_item, 'poc_urls') and vuln_item.poc_urls:
        print("\nPoC/EXP链接:")
        for url in vuln_item.poc_urls:
            print(f"- {url}")
    
    if vuln_item.reference:
        print("\n参考链接:")
        for ref in vuln_item.reference:
            print(f"- {ref}")
    
    print("\n" + "="*50)


# 命令行接口
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python threatbook_premium.py <漏洞ID>")
        print("示例: python threatbook_premium.py CVE-2021-44228")
        print("示例: python threatbook_premium.py XVE-2021-40836")
        sys.exit(1)
    
    vuln_id = sys.argv[1]
    print(f"正在查询漏洞: {vuln_id}")
    
    vuln_item = fetch_premium_vuln(vuln_id)
    if vuln_item:
        print_vuln_detail(vuln_item)
    else:
        print(f"未找到漏洞 {vuln_id} 的信息，请检查漏洞ID是否正确或API密钥是否配置")
        sys.exit(1)