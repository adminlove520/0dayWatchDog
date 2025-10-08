# 更新日志
本文件记录了项目的所有显著变更。

格式基于 [Keep a Changelog](http://keepachangelog.com/)
并遵循 [语义化版本控制](http://semver.org/) 规范。

## [3.0] - 2025-09-26

### 核心功能
- 🚀 **多源数据聚合**：整合CISA、OSCS、奇安信、长亭Rivers和ThreatBook等多个权威漏洞数据源
- 🏢 **智能去重**：基于CVE ID和漏洞名称+日期的双重去重机制
- 🛠️ **灵活配置**：通过环境变量或参数自定义爬取时间范围、输出目录等
- 📊 **报告生成**：自动生成Markdown格式漏洞报告，支持参考链接格式化
- 🚀 **PoC搜索**：集成GitHub PoC/EXP搜索功能，辅助漏洞验证
- 🎨 **定时任务**：支持周期性自动爬取（通过GitHub Actions实现）
