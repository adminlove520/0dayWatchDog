# oscs.py
"""
OSCS 开源安全情报增强版

接口:
    https://www.oscs1024.com/oscs/v1/intelligence/list   (POST, JSON) - 列表接口
    https://www.oscs1024.com/oscs/v1/vdb/vuln_info       (GET) - 漏洞详情基础接口
    https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{mps_id} (GET) - 漏洞详情完整接口

功能:
    - fetch_oscs(date)     —— 按日期抓取 (高危/严重)，支持两级数据获取和CVE提取
    - search_oscs(keyword) —— 关键词 / CVE 搜索，支持两级数据获取和CVE提取
    - get_vuln_detail(mps_id) —— 获取单个漏洞的详细信息
    - extract_cve_from_text(text) —— 从文本中提取CVE编号
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import random
import time
import re
import logging
from models import VulnItem
from utils import _session
from poc_fetcher import fetch_poc_urls

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API接口定义
LIST_API = "https://www.oscs1024.com/oscs/v1/intelligence/list"
VULN_INFO_BASE_API = "https://www.oscs1024.com/oscs/v1/vdb/vuln_info"
VULN_INFO_API_TEMPLATE = "https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{mps_id}"

# 严重程度配置
LEVEL_OK = {"严重", "高危"}  # 可配置是否包含"中危"

# CVE正则表达式模式
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# ------------------------- 内部通用函数 -------------------------

def _post_page(page: int, per_page: int = 100, keyword: str = "") -> dict:
    """
    POST 请求分页列表；服务器 5xx 时重试 ≤ 3 次
    返回形如 {"data":{"data":[…]}} 的最外层 dict
    """
    payload = {"page": page, "per_page": per_page}
    if keyword:
        payload["keyword"] = keyword

    for attempt in range(3):
        try:
            r = _session.post(LIST_API, json=payload, timeout=8)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"[OSCS] page {page} attempt {attempt+1}: {str(e)}")
            if attempt < 2:  # 避免最后一次重试后再等待
                time.sleep(random.uniform(1, 2))
    logger.error(f"[OSCS] Failed to fetch page {page} after 3 attempts")
    return {}

def _get_vuln_info(mps_id: str) -> dict:
    """
    GET 请求漏洞详情；服务器错误时重试 ≤ 3 次
    """
    url = VULN_INFO_API_TEMPLATE.format(mps_id=mps_id)
    for attempt in range(3):
        try:
            r = _session.get(url, timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"[OSCS] get vuln info for {mps_id} attempt {attempt+1}: {str(e)}")
            if attempt < 2:  # 避免最后一次重试后再等待
                time.sleep(random.uniform(1, 2))
    logger.error(f"[OSCS] Failed to fetch vulnerability info for {mps_id} after 3 attempts")
    return {}

def extract_cve_from_text(text: str) -> Optional[str]:
    """
    从文本中提取CVE编号
    """
    if not text or not isinstance(text, str):
        return None
    match = CVE_PATTERN.search(text)
    if match:
        return match.group().upper()
    return None

def _extract_mps_id(url: Optional[str]) -> Optional[str]:
    """
    从URL中提取MPS ID
    """
    if url and isinstance(url, str) and "hd/" in url:
        return url.split("hd/")[-1]
    return None

def _extract_cve_from_item(item: dict) -> Optional[str]:
    """
    尝试从漏洞项的多个字段中提取CVE ID
    """
    # 1. 首先检查是否已有cve_id字段
    if item.get("cve_id"):
        return item["cve_id"]
    
    # 2. 从title中提取
    cve = extract_cve_from_text(item.get("title", ""))
    if cve:
        return cve
    
    # 3. 从description或desc中提取
    for field in ["description", "desc"]:
        if field in item:
            cve = extract_cve_from_text(item[field])
            if cve:
                return cve
    
    # 4. 从reference_url_list中提取
    ref_urls = item.get("reference_url_list", [])
    for ref in ref_urls:
        url_to_check = ref["url"] if isinstance(ref, dict) and "url" in ref else str(ref)
        cve = extract_cve_from_text(url_to_check)
        if cve:
            return cve
    
    return None

def _enhance_vuln_item(item: dict) -> dict:
    """
    增强漏洞数据，添加缺失的字段信息
    """
    # 提取MPS ID（从URL中）
    mps_id = _extract_mps_id(item.get("url"))
    
    # 如果有MPS ID，获取详细信息
    if mps_id:
        detail = _get_vuln_info(mps_id)
        if detail:
            # 合并详情数据到原始item
            item["detail_data"] = detail
            
            # 更新关键字段
            update_fields = ["last_modified_time", "level", "kind", "description", "reference_url_list"]
            for field in update_fields:
                if field in detail:
                    item[field] = detail[field]
    
    # 提取CVE ID（如果还没有）
    if not item.get("cve_id"):
        cve = _extract_cve_from_item(item)
        if cve:
            item["cve_id"] = cve
    
    return item

def _build_reference_urls(item: dict) -> Optional[List[str]]:
    """
    构建参考链接列表，确保不重复
    """
    urls = []
    
    # 添加主URL
    main_url = item.get("url")
    if main_url and isinstance(main_url, str):
        urls.append(main_url)
    
    # 添加reference_url_list中的链接
    ref_urls = item.get("reference_url_list", [])
    if isinstance(ref_urls, list):
        for ref in ref_urls:
            if isinstance(ref, dict) and "url" in ref and ref["url"] not in urls:
                urls.append(ref["url"])
            elif isinstance(ref, str) and ref not in urls:
                urls.append(ref)
    
    return urls if urls else None

def _is_cve_keyword_match(keyword: str, row: dict) -> bool:
    """
    检查CVE关键词是否匹配漏洞项
    """
    # 尝试直接匹配cve_id
    if keyword.lower() == (row.get("cve_id") or "").lower():
        return True
    
    # 尝试从文本字段中提取CVE并匹配
    text_to_search = " ".join(filter(None, [
        row.get("title", ""),
        row.get("description", ""),
        row.get("desc", "")
    ]))
    
    extracted_cve = extract_cve_from_text(text_to_search)
    return extracted_cve is not None and extracted_cve.lower() == keyword.lower()

def _create_vuln_item_from_row(row: dict) -> VulnItem:
    """
    从增强后的漏洞数据行创建VulnItem对象
    """
    # 获取PoC/EXP链接
    cve = row.get("cve_id")
    vuln_name = row.get("title")
    vuln_id = _extract_mps_id(row.get("url"))
    
    poc_urls = fetch_poc_urls(cve, vuln_name, vuln_id)
    
    # 构建参考链接
    reference_urls = _build_reference_urls(row)
    # 添加PoC/EXP链接到参考链接中
    if poc_urls:
        if reference_urls:
            reference_urls.extend([url for url in poc_urls if url not in reference_urls])
        else:
            reference_urls = poc_urls
    
    # 提取日期信息
    date_field = row.get("last_modified_time") or row.get("public_time", "")
    date = date_field.split("T")[0] if date_field else ""
    
    # 创建VulnItem
    return VulnItem(
        name=row["title"],
        cve=row.get("cve_id"),
        date=date,
        severity=row["level"],
        tags=row.get("kind"),  # 使用漏洞类型作为tags
        source="OSCS",
        description=row.get("description") or row.get("desc", ""),
        reference=reference_urls,
    )

# --------------------------- 搜索 ---------------------------

def search_oscs(keyword: str) -> List[VulnItem]:
    """
    关键词搜索:
        - 以 'CVE-' 开头 (忽略大小写) → 精确匹配 cve_id
        - 否则对 title 做包含匹配 (不区分大小写)
    仅保留 level ∈ LEVEL_OK
    支持两级数据获取和CVE提取增强
    """
    if not keyword:
        logger.warning("[OSCS] Empty keyword provided for search")
        return []
        
    vulns: List[VulnItem] = []
    page, per_page = 1, 100
    is_cve = keyword.lower().startswith("cve-")
    processed_count = 0

    while True:
        j = _post_page(page, per_page, keyword)
        rows = j.get("data", {}).get("data", [])
        if not rows:
            break

        for row in rows:
            # 严重程度过滤
            if row.get("level") not in LEVEL_OK:
                continue

            # 关键词匹配过滤
            if is_cve:
                if not _is_cve_keyword_match(keyword, row):
                    continue
            else:
                if keyword.lower() not in (row.get("title", "") or "").lower():
                    continue

            # 增强漏洞数据
            try:
                enhanced_row = _enhance_vuln_item(row)
                vuln_item = _create_vuln_item_from_row(enhanced_row)
                vulns.append(vuln_item)
                processed_count += 1
                
                # 每处理10个项目短暂暂停，避免请求过于频繁
                if processed_count % 10 == 0:
                    time.sleep(0.5)
            except Exception as e:
                logger.error(f"[OSCS] Error processing vulnerability: {str(e)}")
                continue

        page += 1
        
        # 避免过快翻页
        time.sleep(0.3)

    logger.info(f"[OSCS] Found {len(vulns)} vulnerabilities matching keyword '{keyword}'")
    return vulns

# --------------------------- 按日期抓取 ---------------------------

def fetch_oscs(date: str) -> List[VulnItem]:
    """
    返回发布日期 == <date> 且 level ∈ LEVEL_OK 的列表
    支持两级数据获取和CVE提取增强
    对于当日数据，直接调用VULN_INFO_BASE_API接口获取
    """
    if not date or not isinstance(date, str) or len(date) != 10:
        logger.warning(f"[OSCS] Invalid date format: {date}. Expected YYYY-MM-DD")
        return []
        
    vulns: List[VulnItem] = []
    # 用于去重的集合
    unique_vulns = {}
    
    # 1. 对于当日数据，直接调用VULN_INFO_BASE_API接口获取
    today = datetime.now().strftime("%Y-%m-%d")
    if date == today:
        logger.info(f"[OSCS] Fetching today's vulnerabilities directly from {VULN_INFO_BASE_API}")
        try:
            # 尝试直接调用VULN_INFO_BASE_API获取当日数据
            response = _session.get(VULN_INFO_BASE_API, timeout=10)
            response.raise_for_status()
            today_vulns = response.json()
            
            # 处理返回的数据
            if isinstance(today_vulns, list):
                logger.info(f"[OSCS] Direct API returned {len(today_vulns)} items, today is {today}")
            # 打印一些样本数据用于调试
            if today_vulns and len(today_vulns) > 0:
                logger.info(f"[OSCS] Sample item data: {str(today_vulns[0])[:500]}...")
                for idx, vuln_data in enumerate(today_vulns):
                    try:
                        # 提取发布日期，尝试多种可能的字段
                        pub_time = vuln_data.get("published_time", "")
                        
                        # 同时尝试其他可能的日期字段
                        if not pub_time:
                            pub_time = vuln_data.get("public_time", "")
                        
                        logger.info(f"[OSCS] Item {idx+1} pub_time: '{pub_time}', fields: {list(vuln_data.keys())}")
                        
                        # 提取日期部分
                        if pub_time:
                            # 处理ISO格式 2025-11-07T12:34:56
                            if "T" in pub_time:
                                pub_date = pub_time.split("T")[0]
                            # 处理标准格式 2025-11-07
                            elif len(pub_time) >= 10 and pub_time[4] == '-' and pub_time[7] == '-':
                                pub_date = pub_time[:10]
                            else:
                                pub_date = ""
                            logger.info(f"[OSCS] Item {idx+1} extracted pub_date: '{pub_date}', target date: '{date}'")
                        else:
                            pub_date = ""
                            logger.info(f"[OSCS] Item {idx+1} has no publication time")
                        
                        # 检查是否是目标日期，或者如果日期无法确定，至少包含CVE ID的我们也尝试处理
                        if pub_date != date and not (vuln_data.get('cve_id') and date == today):
                            continue
                        logger.info(f"[OSCS] Item {idx+1} matched target date {date}")
                        
                        # 获取严重程度（从cvss或level字段）
                        severity = vuln_data.get("level", "")
                        if not severity and "cvss" in vuln_data:
                            # 尝试从cvss字段获取严重程度
                            for version in ["cvssv3", "cvssv31", "cvssv4"]:
                                if version in vuln_data["cvss"] and isinstance(vuln_data["cvss"][version], list) and len(vuln_data["cvss"][version]) > 0:
                                    severity = vuln_data["cvss"][version][0].get("severity", "").lower()
                                    # 转换严重程度为中文
                                    severity_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
                                    severity = severity_map.get(severity, severity)
                                    break
                        
                        # 打印严重程度信息，但不进行过滤，以确保能捕获所有数据
                        logger.info(f"[OSCS] Item {idx+1} severity: '{severity}', LEVEL_OK: {LEVEL_OK}")
                        logger.info(f"[OSCS] Processing item {idx+1}: {vuln_data.get('cve_id') or vuln_data.get('title', '')}")
                        
                        # 准备数据用于创建VulnItem
                        item_data = {
                            "title": vuln_data.get("title", ""),
                            "cve_id": vuln_data.get("cve_id"),
                            "level": severity,
                            "description": vuln_data.get("description", ""),
                            "kind": vuln_data.get("kind", ""),
                            "last_modified_time": vuln_data.get("last_modified_time", ""),
                            "public_time": vuln_data.get("published_time", ""),
                            "url": f"https://www.oscs1024.com/hd/{vuln_data.get('mps_id', '')}"
                        }
                        
                        # 获取参考链接
                        if "reference_url_list" in vuln_data:
                            item_data["reference_url_list"] = vuln_data["reference_url_list"]
                        
                        # 添加PoC信息
                        if "poc_url" in vuln_data and vuln_data["poc_url"]:
                            poc_urls = vuln_data["poc_url"] if isinstance(vuln_data["poc_url"], list) else [vuln_data["poc_url"]]
                            if "poc_urls" not in item_data:
                                item_data["poc_urls"] = poc_urls
                        
                        # 创建VulnItem
                        vuln_item = _create_vuln_item_from_row(item_data)
                        
                        # 使用CVE或MPS ID作为唯一键
                        unique_key = vuln_item.cve or vuln_data.get("mps_id")
                        if unique_key:
                            unique_vulns[unique_key] = vuln_item
                        else:
                            vulns.append(vuln_item)
                        
                        # 每处理5个项目短暂暂停
                        if (idx + 1) % 5 == 0:
                            time.sleep(0.5)
                    except Exception as e:
                        logger.error(f"[OSCS] Error processing today's vulnerability {idx+1}: {str(e)}")
                        continue
            logger.info(f"[OSCS] Direct fetch filtered {len(unique_vulns)} vulnerabilities for {date}")
        except Exception as e:
            logger.error(f"[OSCS] Error fetching today's vulnerabilities: {str(e)}")
    
    # 2. 保留原有的分页查询逻辑，确保不会丢失数据
    page, per_page = 1, 100
    logger.info(f"[OSCS] Starting paginated fetch for date {date}")
    
    while True:
        j = _post_page(page, per_page)
        rows = j.get("data", {}).get("data", [])
        if not rows:
            break

        for row in rows:
            # 日期和严重程度过滤
            try:
                pub_date = row.get("public_time", "").split("T")[0]
                if pub_date != date or row.get("level") not in LEVEL_OK:
                    continue

                # 增强漏洞数据并创建VulnItem
                enhanced_row = _enhance_vuln_item(row)
                vuln_item = _create_vuln_item_from_row(enhanced_row)
                
                # 使用CVE或从URL提取的MPS ID作为唯一键进行去重
                mps_id = _extract_mps_id(row.get("url"))
                unique_key = vuln_item.cve or mps_id
                if unique_key:
                    unique_vulns[unique_key] = vuln_item
                else:
                    vulns.append(vuln_item)
                
                # 每处理10个项目短暂暂停
                if len(unique_vulns) % 10 == 0:
                    time.sleep(0.5)
            except Exception as e:
                logger.error(f"[OSCS] Error processing vulnerability on {date}: {str(e)}")
                continue

        # 列表按时间倒序；如果最后一条已早于目标日期就不用翻下去了
        if rows and "public_time" in rows[-1]:
            last_date = rows[-1]["public_time"].split("T")[0]
            if last_date < date:
                break

        page += 1
        # 避免过快翻页
        time.sleep(0.3)
    
    # 将去重后的漏洞添加到列表
    if unique_vulns:
        vulns.extend(unique_vulns.values())
    
    # 再次去重，确保不重复
    final_vulns = []
    seen = set()
    for vuln in vulns:
        # 使用CVE+名称作为唯一标识
        key = f"{vuln.cve or 'NOCVE'}_{vuln.name}"
        if key not in seen:
            seen.add(key)
            final_vulns.append(vuln)
    
    logger.info(f"[OSCS] Found {len(final_vulns)} unique vulnerabilities published on {date}")
    return final_vulns

# --------------------------- 获取漏洞详情 ---------------------------

def get_vuln_detail(mps_id: str) -> Optional[VulnItem]:
    """
    根据MPS ID获取单个漏洞的详细信息
    """
    if not mps_id:
        logger.warning("[OSCS] Empty MPS ID provided")
        return None
    
    detail = _get_vuln_info(mps_id)
    if not detail:
        logger.warning(f"[OSCS] No details found for MPS ID: {mps_id}")
        return None
    
    try:
        # 提取CVE ID
        detail["cve_id"] = _extract_cve_from_item(detail)
        
        # 使用通用函数创建VulnItem
        vuln_item = _create_vuln_item_from_row(detail)
        logger.info(f"[OSCS] Successfully retrieved details for MPS ID: {mps_id}")
        return vuln_item
    except Exception as e:
        logger.error(f"[OSCS] Error processing vulnerability details for {mps_id}: {str(e)}")
        return None
