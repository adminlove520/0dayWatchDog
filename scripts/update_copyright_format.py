#!/usr/bin/env python3
"""
更新历史漏洞报告的版权信息格式脚本
用于将现有的版权信息更新为居中格式
"""

import os
import re
from pathlib import Path

def update_copyright_format(content):
    """更新版权信息为居中格式"""
    # 检查是否已经存在居中格式
    if '<div align="center">' in content:
        return content  # 已经居中，无需处理
    
    # 查找现有的版权信息部分
    copyright_pattern = r'(---\s*\n## 版权信息\s*\n.*?东方隐侠安全团队公众号\s*\n.*?wemp\.jpg.*?\n)'
    match = re.search(copyright_pattern, content, re.DOTALL)
    
    if not match:
        return content  # 没有找到版权信息
    
    # 获取旧的版权信息
    old_copyright = match.group(1)
    
    # 创建新的居中版权信息
    new_copyright = """---
<div align="center">

## 版权信息

东方隐侠安全团队（[https://www.dfyxsec.com/](https://www.dfyxsec.com/)）  
Anonymous（[https://github.com/adminlove520](https://github.com/adminlove520)）  
东方隐侠安全团队公众号  
![公众号](../wemp.jpg)

</div>
"""
    
    # 替换版权信息
    new_content = content.replace(old_copyright, new_copyright)
    
    return new_content

def process_all_reports():
    """处理所有历史报告文件"""
    # 获取项目根目录
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    reports_dir = project_root / "vulnerability_reports"
    
    if not reports_dir.exists():
        print(f"错误: {reports_dir} 目录不存在")
        return
    
    # 获取所有子目录中的markdown文件
    all_md_files = []
    for subdir in reports_dir.iterdir():
        if subdir.is_dir() and subdir.name.startswith("vulnerability_report_"):
            md_files = list(subdir.glob("vulnerability_report_*.md"))
            all_md_files.extend(md_files)
    
    # 同时检查daily.md
    daily_file = reports_dir / "daily.md"
    if daily_file.exists():
        all_md_files.append(daily_file)
    
    if not all_md_files:
        print("未找到需要处理的漏洞报告文件")
        return
    
    print(f"找到 {len(all_md_files)} 个报告文件")
    
    # 处理每个文件
    processed = 0
    skipped = 0
    failed = 0
    
    for file_path in all_md_files:
        try:
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 更新版权格式
            new_content = update_copyright_format(content)
            
            if new_content != content:
                # 写回更新后的内容
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                processed += 1
                print(f"已更新: {file_path.name}")
            else:
                skipped += 1
                print(f"跳过: {file_path.name} (无需更新)")
                
        except Exception as e:
            failed += 1
            print(f"处理失败: {file_path.name} - {e}")
    
    print(f"\n处理完成:")
    print(f"已更新: {processed} 个")
    print(f"跳过: {skipped} 个")
    print(f"失败: {failed} 个")

if __name__ == "__main__":
    print("开始更新历史报告的版权信息格式...")
    process_all_reports()
    print("更新完成！")