# 开发计划 (dev分支)

## 当前状态
- 已创建dev分支用于开发和测试
- GitHub API 403/401错误已解决
- 项目可以正常获取CVE数据

## 新想法和改进计划

### 1. 功能增强
- [✅️] 添加基于`threatbook_premium.py`CVE详细信息页面（包括CVSS评分、影响范围、公开poc、修复建议等）
- [✅️] 实现漏洞报告分类存储(根据`vulnerability_reports/vulnerability_report_YYYY-MM-DD/vulnerability_report_YYYY-MM-DD.md`、`vulnerability_reports/daily.md`)
- [❌️] 处理GUI界面相关bug（threatbook中漏洞标签、漏洞等级、漏洞描述、参考链接无法获取问题）
- [✅️] 处理workflow中可通过days_back参数指定爬取时间范围

### 2. 用户体验改进
- [🚧] 优化GUI界面设计
- [🚧] 添加GUI过滤筛选功能
- [🚧] 实现基于github Pages的当日漏洞报告展示及分析功能（UI将于3.0.1c初步实现）


### 3. 扩展功能
- [🚀] 添加邮件通知功能
- [🚀] 实现RSS订阅功能（供东方隐侠客栈订阅使用）
- [🚀] 添加API接口供外部调用（供AI训练数据调用）
- [🚀] 集成推送功能（dingtalk、飞书等）

### 4. 安全性增强
- [ ] 添加输入验证和过滤
- [ ] 实现访问控制机制
- [ ] 添加安全头信息
- [ ] 定期安全审计

## 开发流程
1. 在dev分支进行功能开发和测试
2. 通过Pull Request合并到main分支
3. 定期进行代码审查
4. 发布新版本时打标签

## 注意事项
- 保持与main分支的同步
- 编写单元测试
- 更新相关文档
- 遵循代码规范