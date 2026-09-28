"""急诊跨诊所历史记录的紧急访问：申请、临床批准、短时读取与事后审计。

访问权永远不写入角色权限：它只以一条有时限的申请记录存在，到期、撤销或
申请人账号停用即失效。每次裁决与章节读取同时进入本诊所与来源诊所的哈希链，
读取留痕及事后确认只允许追加，数据库触发器拒绝任何改写或删除。
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from . import audit
from .db import Database, decode_json, encode_json
from .errors import Conflict, Forbidden, NotFound, Unauthorized, ValidationError
from .exports import PatientExportService
from .ids import new_id, require_id, require_idempotency_key
from .security import ROLE_PERMISSIONS, authorize, principal_for
from .validation import choice, integer, parsed_timestamp, request_digest, require_match, text, timestamp

# 可申请的资料章节与导出白名单保持一致，另含急诊常用的安全关注项与就诊记录。
EMERGENCY_SECTIONS = {
    "profile", "consents", "assessments", "plans", "observations",
    "appointments", "followups", "incidents", "clinical_flags", "encounters",
}
REQUEST_ROLES = {"owner", "clinician", "nurse", "coordinator"}
APPROVAL_ROLES = {"owner", "clinician"}
MIN_TTL_MINUTES = 5
MAX_TTL_MINUTES = 120


class _AccessInvalid(Exception):
    """写事务围栏失败的内部信号；携带行快照供事务外留痕。"""

    def __init__(self, snapshot: dict, reason: str, *, expired: bool = False):
        super().__init__(reason)
        self.snapshot = snapshot
        self.reason = reason
        self.expired = expired


class EmergencyAccessService:
    def __init__(self, database: Database, clock):
        self.db = database
        self.clock = clock

    # ---------------------------------------------------------------- 申请

    def request_access(self, clinic_id: str, actor_id: str, source_clinic_id: str, patient_id: str,
                       clinical_reason: str, sections: list[str], ttl_minutes: int,
                       idempotency_key: str) -> dict[str, Any]:
        source_clinic_id = require_id(source_clinic_id, "来源诊所编号")
        patient_id = require_id(patient_id, "患者编号")
        reason = text(clinical_reason, "临床处置原因", minimum=10, maximum=1000)
        sections = self._normalize_sections(sections)
        ttl = integer(ttl_minutes, "申请访问时长", minimum=MIN_TTL_MINUTES, maximum=MAX_TTL_MINUTES)
        key = require_idempotency_key(idempotency_key)
        request_id = new_id("emr")
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if principal.role not in REQUEST_ROLES:
                raise Forbidden("当前岗位不能申请紧急临床访问")
            if source_clinic_id == clinic_id:
                raise ValidationError("紧急访问仅用于其他诊所建立的历史记录")
            if connection.execute("SELECT 1 FROM clinics WHERE id=?", (source_clinic_id,)).fetchone() is None:
                raise NotFound("来源诊所不存在")
            patient = connection.execute(
                "SELECT id FROM patients WHERE id=? AND clinic_id=?", (patient_id, source_clinic_id)).fetchone()
            if patient is None:
                # 已认证的本院人员在申请场景下得到明确校验结果，不扩大为匿名侧信道。
                raise NotFound("来源诊所中不存在该患者")
            stored_key = f"{clinic_id}:{actor_id}:{key}"
            old = connection.execute(
                "SELECT * FROM idempotency WHERE scope='emergency_request' AND key=?", (stored_key,)).fetchone()
            request_body = {"clinic_id": clinic_id, "actor_id": actor_id, "source_clinic_id": source_clinic_id,
                           "patient_id": patient_id, "clinical_reason": reason, "sections": sections,
                           "ttl_minutes": ttl}
            body_hash = request_digest(request_body)
            if old:
                if old["request_hash"] != body_hash:
                    raise Conflict("紧急申请幂等编号已用于其他请求")
                # 重放不写入任何内容、不延长授权；返回申请的当前状态（批准/到期不会改变原到期时间）。
                live = connection.execute(
                    "SELECT * FROM emergency_access_requests WHERE id=?",
                    (decode_json(old["response_json"])["id"],)).fetchone()
                if live is None:
                    raise NotFound("紧急申请不存在")
                return {**self._serialize(live), "replayed": True}
            connection.execute(
                "INSERT INTO emergency_access_requests(id,clinic_id,requestor_id,source_clinic_id,patient_id,"
                "clinical_reason,requested_sections_json,ttl_minutes,state,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,'requested',?)",
                (request_id, clinic_id, actor_id, source_clinic_id, patient_id, reason,
                 encode_json(sections), ttl, now))
            payload = {"requestor_id": actor_id, "source_clinic_id": source_clinic_id, "patient_id": patient_id,
                       "clinical_reason": reason, "requested_sections": sections, "ttl_minutes": ttl}
            self._audit(connection, home_clinic=clinic_id, source_clinic=source_clinic_id, actor=actor_id,
                        patient_id=patient_id, aggregate_id=request_id, action="emergency.requested",
                        now=now, payload=payload)
            result = self._serialize(connection.execute(
                "SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone())
            connection.execute(
                "INSERT INTO idempotency(scope,key,request_hash,response_json,created_at) "
                "VALUES('emergency_request',?,?,?,?)",
                (stored_key, body_hash, encode_json(result), now))
        return {**result, "replayed": False}

    # ---------------------------------------------------------------- 批准/拒绝

    def decide(self, clinic_id: str, actor_id: str, request_id: str, decision: str, *,
               expected_version: int, note: str | None = None,
               granted_sections: list[str] | None = None,
               granted_ttl_minutes: int | None = None) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急申请编号")
        decision = choice(decision, "批准决定", {"approve", "deny"})
        note = text(note or "", "批准说明", minimum=0, maximum=1000)
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if principal.role not in APPROVAL_ROLES:
                raise Forbidden("只有值班临床负责人可以批准紧急访问")
            row = self._fetch_owned(connection, clinic_id, request_id)
            if row["state"] != "requested":
                raise Conflict("该申请已有结论，不能重复裁决", details={"state": row["state"]})
            if row["version"] != expected_version:
                require_match(row["version"], expected_version, "紧急申请")
            # 申请人与批准人不能是同一人。
            if row["requestor_id"] == actor_id:
                raise Forbidden("紧急访问必须由另一位值班临床负责人批准")
            requestor = connection.execute(
                "SELECT active FROM staff WHERE id=? AND clinic_id=?", (row["requestor_id"], clinic_id)).fetchone()
            if requestor is None or not requestor["active"]:
                raise Conflict("申请人账号已停用，申请不能生效")
            requested_sections = decode_json(row["requested_sections_json"])
            if decision == "deny":
                denial_reason = text(note, "拒绝原因", minimum=5, maximum=1000)
                connection.execute(
                    "UPDATE emergency_access_requests SET state='denied',decided_at=?,approver_id=?,"
                    "approval_note=?,version=version+1 WHERE id=?",
                    (now, actor_id, denial_reason, request_id))
                payload = {"requestor_id": row["requestor_id"], "reason": denial_reason}
                self._audit(connection, home_clinic=clinic_id, source_clinic=row["source_clinic_id"],
                            actor=actor_id, patient_id=row["patient_id"], aggregate_id=request_id,
                            action="emergency.denied", now=now, payload=payload)
            else:
                granted = self._normalize_sections(
                    granted_sections if granted_sections is not None else requested_sections, field="授予章节")
                if not set(granted) <= set(requested_sections):
                    raise ValidationError("授予章节不能超出申请范围")
                granted_ttl = integer(granted_ttl_minutes, "授予访问时长",
                                      minimum=MIN_TTL_MINUTES, maximum=MAX_TTL_MINUTES) \
                    if granted_ttl_minutes is not None else row["ttl_minutes"]
                if granted_ttl > row["ttl_minutes"]:
                    raise ValidationError("授予时长不能超过申请时长")
                expires = timestamp(parsed_timestamp(now) + timedelta(minutes=granted_ttl))
                connection.execute(
                    "UPDATE emergency_access_requests SET state='active',decided_at=?,approver_id=?,"
                    "approval_note=?,granted_sections_json=?,granted_ttl_minutes=?,grant_started_at=?,"
                    "grant_expires_at=?,version=version+1 WHERE id=?",
                    (now, actor_id, note or None, encode_json(granted), granted_ttl, now, expires, request_id))
                payload = {"requestor_id": row["requestor_id"], "granted_sections": granted,
                           "granted_ttl_minutes": granted_ttl, "grant_expires_at": expires,
                           "approval_note": note or None}
                self._audit(connection, home_clinic=clinic_id, source_clinic=row["source_clinic_id"],
                            actor=actor_id, patient_id=row["patient_id"], aggregate_id=request_id,
                            action="emergency.approved", now=now, payload=payload)
            return self._serialize(connection.execute(
                "SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone())

    # ---------------------------------------------------------------- 读取

    def read_section(self, clinic_id: str, actor_id: str, request_id: str, section: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急申请编号")
        section = choice(section, "资料章节", EMERGENCY_SECTIONS)
        now = timestamp(self.clock.now())
        # 第一阶段：只读判定并提取数据；任何失效留待读事务结束后再持久化。
        invalid = None
        with self.db.transaction(write=False) as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if not principal.active:
                raise Unauthorized("账号已停用")
            row = self._fetch_owned(connection, clinic_id, request_id)
            invalid = self._classify(row, actor_id, section, now)
            if invalid is None:
                patient = connection.execute(
                    "SELECT * FROM patients WHERE id=? AND clinic_id=?",
                    (row["patient_id"], row["source_clinic_id"])).fetchone()
                if patient is None:
                    # 档案不会被物理删除；若异常缺失则拒绝且不留数据出口。
                    raise NotFound("来源患者档案不存在")
                data = self._extract_section(connection, section, patient)
                source_clinic_id = row["source_clinic_id"]
                patient_id = row["patient_id"]
                grant_expires_at = row["grant_expires_at"]
        if invalid is not None:
            self._handle_invalid(clinic_id, request_id, invalid, actor_id, section, now)
        # 第二阶段：独占写事务中再次 fencing，通过后才追加读取留痕。
        try:
            with self.db.transaction() as connection:
                staff = connection.execute(
                    "SELECT active FROM staff WHERE id=? AND clinic_id=?", (actor_id, clinic_id)).fetchone()
                if staff is None or not staff["active"]:
                    raise Unauthorized("账号已停用")
                row = self._fetch_owned(connection, clinic_id, request_id)
                late_invalid = self._classify(row, actor_id, section, now)
                if late_invalid is not None:
                    raise late_invalid
                read_id = new_id("emrd")
                connection.execute(
                    "INSERT INTO emergency_access_reads(id,request_id,clinic_id,source_clinic_id,patient_id,reader_id,section,accessed_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (read_id, request_id, clinic_id, row["source_clinic_id"], row["patient_id"], actor_id, section, now))
                self._audit(connection, home_clinic=clinic_id, source_clinic=row["source_clinic_id"], actor=actor_id,
                            patient_id=row["patient_id"], aggregate_id=request_id, action="emergency.section_read",
                            now=now, payload={"section": section, "read_id": read_id, "actor_id": actor_id})
        except _AccessInvalid as invalid:
            # 写事务已回滚；在独立事务中把这次被拒绝的读取持久化后再拒绝调用方。
            self._handle_invalid(clinic_id, request_id, invalid, actor_id, section, now)
        return {"request_id": request_id, "patient_id": patient_id,
                "source_clinic_id": source_clinic_id, "section": section,
                "accessed_at": now, "grant_expires_at": grant_expires_at, "data": data}

    def _handle_invalid(self, clinic_id: str, request_id: str, invalid: "_AccessInvalid",
                        actor_id: str, section: str, now: str) -> None:
        if invalid.snapshot["state"] == "active" and invalid.expired:
            self._expire_request(request_id, now)
        self._record_read_denied(clinic_id, invalid.snapshot, actor_id, section, now, invalid.reason)
        if invalid.expired:
            raise Forbidden("紧急访问已到期")
        if invalid.snapshot["state"] == "requested":
            raise Conflict("紧急申请尚未批准")
        if invalid.snapshot["state"] == "revoked":
            raise Forbidden("紧急访问已被撤销", details={"reason": invalid.snapshot.get("revocation_reason")})
        raise Forbidden(invalid.reason)

    @staticmethod
    def _classify(row, actor_id: str, section: str, now: str) -> "_AccessInvalid | None":
        snapshot = {"id": row["id"], "clinic_id": row["clinic_id"], "source_clinic_id": row["source_clinic_id"],
                    "patient_id": row["patient_id"], "state": row["state"],
                    "revocation_reason": row["revocation_reason"]}
        if row["requestor_id"] != actor_id:
            return _AccessInvalid(snapshot, "只有申请人本人可以使用该紧急访问")
        if row["state"] == "requested":
            return _AccessInvalid(snapshot, "紧急申请尚未批准")
        if row["state"] == "denied":
            return _AccessInvalid(snapshot, "紧急访问申请已被拒绝")
        if row["state"] == "revoked":
            return _AccessInvalid(snapshot, f"紧急访问已被撤销：{row['revocation_reason']}")
        if row["state"] == "expired" or parsed_timestamp(row["grant_expires_at"]) <= parsed_timestamp(now):
            return _AccessInvalid(snapshot, "访问窗口已到期", expired=True)
        granted = decode_json(row["granted_sections_json"])
        if section not in granted:
            return _AccessInvalid(snapshot, "该章节不在授予范围内")
        return None

    # ---------------------------------------------------------------- 撤销

    def revoke(self, clinic_id: str, actor_id: str, request_id: str, reason: str, *,
               expected_version: int | None = None) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急申请编号")
        reason = text(reason, "撤销原因", minimum=5, maximum=1000)
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            # 患者安全负责人职责由诊所负责人承担；审核岗位与临床岗位均无此权。
            if principal.role != "owner":
                raise Forbidden("只有患者安全负责人可以撤销紧急访问")
            row = self._fetch_owned(connection, clinic_id, request_id)
            if expected_version is not None and row["version"] != expected_version:
                require_match(row["version"], expected_version, "紧急申请")
            if row["state"] != "active":
                raise Conflict("只有生效中的紧急访问可以撤销", details={"state": row["state"]})
            self._mark_revoked(connection, row, actor_id=actor_id, now=now, reason=reason)
            return self._serialize(connection.execute(
                "SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone())

    def revoke_for_disabled_staff(self, connection, clinic_id: str, staff_id: str, actor_id: str,
                                  now: str) -> list[str]:
        """账号停用的同事务钩子：该员工所有紧急授权立即失效并留痕。"""
        rows = connection.execute(
            "SELECT * FROM emergency_access_requests WHERE clinic_id=? AND requestor_id=? AND state IN ('active','requested')",
            (clinic_id, staff_id)).fetchall()
        revoked_ids = []
        for row in rows:
            reason = "申请人账号停用，紧急访问立即失效"
            connection.execute(
                "UPDATE emergency_access_requests SET state='revoked',revoked_at=?,revoked_by=?,"
                "revocation_reason=?,version=version+1 WHERE id=? AND state IN ('active','requested')",
                (now, actor_id, reason, row["id"]))
            self._audit(connection, home_clinic=clinic_id, source_clinic=row["source_clinic_id"],
                        actor=actor_id, patient_id=row["patient_id"], aggregate_id=row["id"],
                        action="emergency.revoked", now=now,
                        payload={"reason": reason, "requestor_id": staff_id, "trigger": "account_disabled"})
            revoked_ids.append(row["id"])
        return revoked_ids

    # ---------------------------------------------------------------- 到期清扫

    def sweep_expired(self, clinic_id: str, actor_id: str, *, limit: int = 200) -> dict[str, Any]:
        if not 1 <= limit <= 1000:
            raise ValidationError("处理数量必须为 1 至 1000")
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "audit:read", clinic_id=clinic_id)
            rows = connection.execute(
                "SELECT * FROM emergency_access_requests WHERE clinic_id=? AND state='active' "
                "AND grant_expires_at<=? ORDER BY grant_expires_at,id LIMIT ?",
                (clinic_id, now, limit)).fetchall()
            for row in rows:
                self._mark_expired(connection, row, now, reason="访问窗口到期")
        return {"expired": len(rows), "as_of": now}

    # ---------------------------------------------------------------- 事后审计确认

    def review(self, clinic_id: str, actor_id: str, request_id: str, conclusion: str, note: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急申请编号")
        conclusion = choice(conclusion, "审计结论", {"appropriate", "inappropriate"})
        note = text(note, "审计确认说明", minimum=5, maximum=2000)
        now = timestamp(self.clock.now())
        review_id = new_id("emrv")
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            if principal.role != "auditor":
                raise Forbidden("事后确认必须由审计岗位完成")
            row = self._fetch_owned(connection, clinic_id, request_id)
            if row["state"] == "requested":
                raise Conflict("申请尚未裁决，不能进行事后确认")
            # 事后确认必须由另一位审计人员完成：申请人、批准人均不能确认自己参与的访问。
            if actor_id in {row["requestor_id"], row["approver_id"]}:
                raise Forbidden("审计确认必须由未参与该次访问的第三方人员完成")
            if connection.execute(
                "SELECT 1 FROM emergency_access_reviews WHERE request_id=? AND reviewer_id=?",
                (request_id, actor_id)).fetchone():
                raise Conflict("该审计人员已确认过本次访问")
            connection.execute(
                "INSERT INTO emergency_access_reviews(id,request_id,clinic_id,reviewer_id,conclusion,note,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (review_id, request_id, clinic_id, actor_id, conclusion, note, now))
            self._audit(connection, home_clinic=clinic_id, source_clinic=row["source_clinic_id"], actor=actor_id,
                        patient_id=row["patient_id"], aggregate_id=request_id, action="emergency.reviewed",
                        now=now, payload={"review_id": review_id, "conclusion": conclusion, "note": note})
        return {"id": review_id, "request_id": request_id, "reviewer_id": actor_id,
                "conclusion": conclusion, "note": note, "created_at": now}

    # ---------------------------------------------------------------- 查询

    def list_requests(self, clinic_id: str, actor_id: str, *, state: str | None = None,
                      limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 300))
        if state is not None:
            state = choice(state, "申请状态", {"requested", "active", "denied", "expired", "revoked"})
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "audit:read", clinic_id=clinic_id)
            if state:
                rows = connection.execute(
                    "SELECT * FROM emergency_access_requests WHERE clinic_id=? AND state=? ORDER BY created_at DESC,id LIMIT ?",
                    (clinic_id, state, limit)).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM emergency_access_requests WHERE clinic_id=? ORDER BY created_at DESC,id LIMIT ?",
                    (clinic_id, limit)).fetchall()
            return [self._serialize(row) for row in rows]

    def request_detail(self, clinic_id: str, actor_id: str, request_id: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急申请编号")
        with self.db.transaction(write=False) as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            row = self._fetch_owned(connection, clinic_id, request_id)
            is_auditor = "audit:read" in ROLE_PERMISSIONS.get(principal.role, set())
            if not is_auditor and row["requestor_id"] != actor_id:
                raise Forbidden("只能查看本人提交的紧急申请")
            reads = connection.execute(
                "SELECT id,section,reader_id,accessed_at FROM emergency_access_reads WHERE request_id=? ORDER BY accessed_at,id",
                (request_id,)).fetchall()
            reviews = connection.execute(
                "SELECT id,reviewer_id,conclusion,note,created_at FROM emergency_access_reviews WHERE request_id=? ORDER BY created_at,id",
                (request_id,)).fetchall()
            result = self._serialize(row)
            result["reads"] = [dict(item) for item in reads]
            result["reviews"] = [dict(item) for item in reviews]
            return result

    # ---------------------------------------------------------------- 内部辅助

    def _fetch_owned(self, connection, clinic_id: str, request_id: str):
        row = connection.execute(
            "SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?", (request_id, clinic_id)).fetchone()
        if row is None:
            raise NotFound("紧急申请不存在")
        return row

    def _mark_expired(self, connection, row, now: str, *, reason: str) -> None:
        changed = connection.execute(
            "UPDATE emergency_access_requests SET state='expired',version=version+1 "
            "WHERE id=? AND state='active'", (row["id"],)).rowcount
        if changed:
            self._audit(connection, home_clinic=row["clinic_id"], source_clinic=row["source_clinic_id"],
                        actor=None, patient_id=row["patient_id"], aggregate_id=row["id"],
                        action="emergency.expired", now=now,
                        payload={"reason": reason, "grant_expires_at": row["grant_expires_at"]})

    def _expire_request(self, request_id: str, now: str) -> None:
        with self.db.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone()
            if row is not None and row["state"] == "active":
                self._mark_expired(connection, row, now, reason="访问窗口到期")

    def _record_read_denied(self, home_clinic: str, row, actor_id: str, section: str, now: str,
                            reason: str) -> None:
        """被拒绝的读取也必须留痕；独立事务确保随后抛出的异常不会回滚该记录。"""
        with self.db.transaction() as connection:
            self._audit(connection, home_clinic=home_clinic, source_clinic=row["source_clinic_id"],
                        actor=actor_id, patient_id=row["patient_id"], aggregate_id=row["id"],
                        action="emergency.read_denied", now=now,
                        payload={"section": section, "reason": reason, "actor_id": actor_id,
                                 "request_state": row["state"]})

    def _mark_revoked(self, connection, row, *, actor_id: str | None, now: str, reason: str) -> None:
        connection.execute(
            "UPDATE emergency_access_requests SET state='revoked',revoked_at=?,revoked_by=?,"
            "revocation_reason=?,version=version+1 WHERE id=?",
            (now, actor_id, reason, row["id"]))
        self._audit(connection, home_clinic=row["clinic_id"], source_clinic=row["source_clinic_id"],
                    actor=actor_id, patient_id=row["patient_id"], aggregate_id=row["id"],
                    action="emergency.revoked", now=now,
                    payload={"reason": reason, "requestor_id": row["requestor_id"]})

    @staticmethod
    def _audit(connection, *, home_clinic: str, source_clinic: str, actor: str | None, patient_id: str,
               aggregate_id: str, action: str, now: str, payload: dict[str, Any]) -> None:
        """本诊所链记录治理动作；来源诊所链同步记录一次对外披露。

        来源诊所链上的 actor 置空：该员工不属于来源诊所，避免跨库外键；实际操作人
        写入载荷中的 requestor/actor 字段，仍可在两个诊所的链上逐事件对账。
        """
        audit.append_event(connection, clinic_id=home_clinic, actor_id=actor, patient_id=patient_id,
                           aggregate_type="emergency_access", aggregate_id=aggregate_id, action=action,
                           occurred_at=now, payload=payload)
        if source_clinic != home_clinic:
            mirrored = {**payload, "requesting_clinic_id": home_clinic}
            if actor is not None:
                mirrored = {"actor_staff_id": actor, **mirrored}
            audit.append_event(connection, clinic_id=source_clinic, actor_id=None, patient_id=patient_id,
                               aggregate_type="emergency_access", aggregate_id=aggregate_id, action=action,
                               occurred_at=now, payload=mirrored)

    @staticmethod
    def _normalize_sections(sections: Any, *, field: str = "资料范围") -> list[str]:
        if not isinstance(sections, list) or not sections:
            raise ValidationError(f"{field}必须指定至少一个章节")
        if len(sections) > len(EMERGENCY_SECTIONS):
            raise ValidationError(f"{field}章节数量超出限制")
        selected = [choice(item, field, EMERGENCY_SECTIONS) for item in sections]
        normalized = sorted(set(selected))
        if len(normalized) != len(sections):
            raise ValidationError(f"{field}章节不能重复")
        return normalized

    @staticmethod
    def _extract_section(connection, section: str, patient) -> Any:
        if section in {"clinical_flags", "encounters"}:
            return EmergencyAccessService._extra_section(connection, section, patient["id"])
        return PatientExportService._section(connection, section, patient)

    @staticmethod
    def _extra_section(connection, section: str, patient_id: str):
        if section == "clinical_flags":
            rows = connection.execute(
                "SELECT id,category,severity,detail,state,effective_from,effective_until,reported_by,"
                "reviewed_by,reviewed_at,resolution_reason,created_at,version "
                "FROM clinical_flags WHERE patient_id=? ORDER BY effective_from,id", (patient_id,)).fetchall()
            return [dict(row) for row in rows]
        rows = connection.execute(
            "SELECT id,appointment_id,state,opened_by,opened_at,signed_by,signed_at,version "
            "FROM encounters WHERE patient_id=? ORDER BY opened_at,id", (patient_id,)).fetchall()
        encounters = [dict(row) for row in rows]
        for encounter in encounters:
            notes = connection.execute(
                "SELECT id,section,body,author_id,revision,created_at,supersedes FROM encounter_notes "
                "WHERE encounter_id=? ORDER BY section,revision", (encounter["id"],)).fetchall()
            encounter["notes"] = [dict(note) for note in notes]
        return encounters

    @staticmethod
    def _serialize(row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "clinic_id": row["clinic_id"],
            "requestor_id": row["requestor_id"],
            "source_clinic_id": row["source_clinic_id"],
            "patient_id": row["patient_id"],
            "clinical_reason": row["clinical_reason"],
            "requested_sections": decode_json(row["requested_sections_json"]),
            "granted_sections": decode_json(row["granted_sections_json"]) if row["granted_sections_json"] else None,
            "ttl_minutes": row["ttl_minutes"],
            "granted_ttl_minutes": row["granted_ttl_minutes"],
            "state": row["state"],
            "created_at": row["created_at"],
            "decided_at": row["decided_at"],
            "approver_id": row["approver_id"],
            "approval_note": row["approval_note"],
            "grant_started_at": row["grant_started_at"],
            "grant_expires_at": row["grant_expires_at"],
            "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"],
            "revocation_reason": row["revocation_reason"],
            "version": row["version"],
        }
