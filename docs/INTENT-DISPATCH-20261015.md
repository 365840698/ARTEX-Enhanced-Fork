# 活跃意图去重与事务化派发

## 解决的问题
planner 提示词此前要求避免重复方向，但 add_intent 每次调用都创建新节点；并发调用、同一批次重复和工具重试可能产生多个相同待执行意图。原创建路径还会忽略上游关联写入错误，留下缺少血缘的节点。

## 新行为
- 任务内按 summary（只剥首尾空白）、资产 ID 集合和前置事实/发现 ID 集合确定派发身份。ID 顺序和重复值不影响身份，优先级不影响身份。
- 对 open/running/paused 的相同意图返回原 ID，不再新增节点，也不因重复请求提高优先级、重启任务或绕过暂停。
- add_intent 批量结果保留 ids/errors，新增同序 created 布尔数组；单条重复返回 already active 和原 ID，明确说明未新增工作。
- 新前置事实、不同资产或不同方向仍创建新工作。done/blocked/exhausted/stopped/deleted 意图不会阻止新一轮显式测试。
- advisory transaction lock 在数据库中串行化相同任务/身份的并发派发；意图、资产关联和全部上游边同事务提交，失败全部回滚。
- 增加仅针对活跃意图的查询索引，随既有启动迁移流程自动建立。

## 边界
这是严格身份去重，不是语义相似度判断：不同措辞不会被模糊合并，大小写和内部空白保持区分，避免把不同 URL/参数误认作相同工作。旧节点不回填身份键，legacy AddIntent 用于种子/人工入口的行为保持不变。前置节点内容原地修改但 ID 不变时，不会产生新的活跃派发身份；需要新事实 ID 或明确的新方向。未新增按“无新事实”自动停任务的策略，也未改变审批和范围校验。

## 验证
单元测试覆盖身份集合规范化和不同条件隔离。PostgreSQL 测试覆盖 12 路并发只有一个新增节点、关联完整性、活跃状态复用、终态重测、前置事实变化、失败回滚和任务间隔离。Agent 工具测试验证批量重复反馈及只在新增工作时恢复任务。CI 额外运行既有跨任务事实/资产上下文回归，防止事务化派发破坏血缘。

    go test -race ./db -run 'TestIntentDispatch' -count=1
    go test -race ./agent -run 'TestIntentDispatchToolReportsReuse|TestGraphOverviewExpandsAssociatedCompanyScope|TestBlackboardToolsReadDirectSources' -count=1

集成测试需要 ARTEX_PG_DSN；无本地数据库时跳过，远端 CI 提供 PostgreSQL 16。
