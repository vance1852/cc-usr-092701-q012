# 服务接口

所有时间使用带时区的 ISO 8601 格式。服务持久化 UTC 时间，按诊所配置的时区解释运营日期。JSON 请求大小上限为 1 MB；无效请求返回稳定的错误码和 HTTP 状态，不向调用方透出数据库异常。

## 登录与诊所隔离

`POST /auth/token` 接受 `staff_id` 和 `password`，返回有效期不超过一天的 Bearer 凭据。除登录与健康检查外，请求必须同时提供 `Authorization: Bearer …` 和 `X-Clinic-ID`。认证失败不区分账号不存在、停用或密码错误；诊所边界之外的数据返回不存在，避免泄露另一诊所的记录。

`POST /auth/logout` 撤销当前凭据。修改员工密码会撤销该员工的全部活动凭据。初始负责人通过命令行创建；没有可直接注册负责人的 HTTP 路由。

## 患者、评估与诊疗计划

- `POST /patients` 建立诊所内患者档案；外部编号在诊所范围内唯一。
- `GET /patients/{patient_id}` 返回最小档案，不返回联系方式密文。
- `POST /patients/{patient_id}/merge` 以两个版本号和书面原因将重复档案标记为合并，并指向保留档案。
- `POST /patients/{patient_id}/assessments` 新建评估草稿；`POST /assessments/{assessment_id}/sign` 由临床岗位签署。
- `POST /patients/{patient_id}/consents` 创建更高版本的授权；`POST /consents/{consent_id}/withdraw` 撤回授权。
- `POST /patients/{patient_id}/plans` 建立计划，医美和体重管理计划必须引用当前对应授权。
- `POST /plans/{plan_id}/{propose|activate|pause|resume|complete|cancel}` 以 `expected_version` 执行带版本保护的状态转换。
- `GET /patients/{patient_id}/weight-series` 返回按观察时间排序的测量值，不生成诊断或治疗建议。

评估签署后不可覆盖。就诊病历由章节组成，签署需要主诉、评估和计划三部分；签署后的补充内容成为新版本，原始文字仍保留。

## 预约、随访与计划节点

创建预约须提供 `Idempotency-Key`，有责任人的预约不能与未结束时段重叠。临时占位到期后由 `POST /appointments/{id}/book` 拒绝确认，过期占位可通过服务方法按限额释放。预约状态按占位、确认、到诊、服务、完成推进；开始服务时产生就诊记录。

随访和计划节点支持领取租约、版本校验、幂等创建、延期和完整处置历史。旧领取者不能以过期令牌提交结果；重新领取不会删除前次领取事件。

## 诊所耗材

- `POST /products` 登记耗材；`POST /products/{product_id}/lots` 按批号入库。
- `POST /stock/reserve` 依据失效日期按先到期先出分批预留，需要 `Idempotency-Key`。
- `POST /stock/{reservation_id}/consume` 记录患者使用；`release` 释放尚未使用的数量。
- `POST /stock/{lot_id}/quarantine`、`recall` 或 `release-quarantine` 记录批次处置及受影响预留。
- `GET /stock/lots` 查看可用数量；`GET /stock/{lot_id}/history` 查看批次流水。

入库、占用、释放与患者使用均进入不可变流水。存在不足时整笔预留回滚；被隔离、召回或在诊所本地日期已过期的批次不能继续使用。

## 不良事件与数据使用

护理人员可报告事件或患者安全关注项；临床岗位复核并记录处置，诊所负责人可作废就诊记录。`GET /audit/verify` 校验诊所哈希链，`GET /audit/diagnostics` 汇报需人工核对的一致性问题，不自动修改业务状态。

`POST /patients/{patient_id}/export` 只在存在有效数据导出授权时返回明确选择的章节。导出字段采用白名单，联系方式密文、凭据和内部合并字段不会导出；相同幂等请求得到相同内容摘要。`GET /reports/daily`、`appointments`、`incidents` 和 `overdue-milestones` 仅返回运营汇总或经岗位授权的工作队列。

## 紧急跨诊所访问

夜间接诊人员偶发需要查阅其他诊所建立的患者历史记录时，不扩大任何常规角色权限，而是走一条独立、短时、双人的紧急访问流程：

1. `POST /emergency-access/requests`（`Idempotency-Key`）由申请人指定 `source_clinic_id`、`patient_id`、`clinical_reason`（临床处置原因）、`sections`（所需资料范围）和 `ttl_minutes`（5–120 分钟）。不能申请本诊所的记录。
2. `POST /emergency-access/requests/{id}/decide` 由值班临床负责人（医生或诊所负责人）裁决：`decision=approve|deny`。批准可缩小章节范围、缩短时长，但不能扩大；拒绝必须填写原因。**申请人与批准人不能是同一人**，护理、协调、审计岗位均不能批准。
3. 批准后申请人通过 `POST /emergency-access/requests/{id}/read` 逐章节读取，每次成功读取单独记录章节与时间；超出授予范围、未批准、已拒绝、已到期或已撤销的读取返回 403/409，并同样写入审计轨迹。

访问在以下任一时刻立即失效：到达 `grant_expires_at`（读取时惰性转过期，`POST /emergency-access/sweep-expired` 可批量清扫）、患者安全负责人（诊所负责人）通过 `POST /emergency-access/requests/{id}/revoke` 撤销、或申请人账号被停用（停用事务内同步撤销其全部待批与生效中的申请）。**重放相同的申请请求只返回原申请的当前状态，不会重新计时或延长旧授权**；用同一幂等键提交不同内容会被拒绝。

事后由独立审计人员通过 `POST /emergency-access/requests/{id}/review` 给出 `appropriate|inappropriate` 确认：申请人本人和批准人都不能确认自己参与的访问，每位审计人员对同一次访问只能确认一次。`GET /emergency-access/requests`（审计岗位）与 `GET /emergency-access/requests/{id}`（审计岗位或申请人本人）返回申请依据、授予范围、到期时间、撤销原因、逐次读取章节和审计确认。

所有裁决、读取、拒绝、到期、撤销与确认事件同时写入申请人所在诊所和来源诊所的哈希链（来源诊所链上操作人在载荷中归属）。读取留痕、确认记录和申请记录在数据库层只允许追加，触发器拒绝 UPDATE 与 DELETE；审计确认是独立追加记录，任何角色都不能改写或删除原始访问轨迹。

## 主要状态

- 计划：草稿 → 提议 → 生效；可暂停和恢复，完成或取消后不能重新激活。
- 预约：占位 → 确认 → 到诊 → 服务中 → 完成；取消和未到诊是独立终态。
- 不良事件：已报告 → 分诊 → 观察 → 已解决 → 关闭。每次处置单独记录操作人和理由。
- 耗材预留：预留 → 释放或核销。库存数量由收货、预留、释放和更正流水求和，不直接改写历史数量。
- 紧急访问：已申请 → 生效（批准后计时）或已拒绝；生效 → 已到期 / 已撤销。待批申请在账号停用时也直接转为已撤销。全部状态迁移与读取动作进入双方诊所的哈希链。
