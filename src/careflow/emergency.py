"""紧急跨诊所病历访问（break-glass）。

夜间接诊人员可申请读取非本诊所建立的患者记录。申请必须指定患者、临床处置
原因和所需资料章节；值班临床负责人双人批准后获得短时授权。访问到期、患者
安全负责人撤销或账号停用时立即失效。每次实际读取（含被拒绝的读取）均留痕，
事后由另一位审计人员确认；申请、决定、读取与复核均进入不可变哈希链，任何
角色都不能修改或删除这些轨迹。
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any, Callable

from . import audit
from .db import Database, decode_json, encode_json
from .errors import Conflict, Forbidden, NotFound, ValidationError
from .ids import new_id, require_id, require_idempotency_key
from .security import authorize, principal_for
from .validation import choice, parsed_timestamp, text, timestamp

# 可申请的资料章节，复用导出服务的白名单口径。
SECTIONS = {"profile", "consents", "assessments", "plans", "observations",
            "appointments", "followups", "incidents", "clinical_flags", "encounters"}
CLINICAL_ROLES = {"owner", "clinician"}
MIN_MINUTES = 15
MAX_MINUTES = 240

# 章节数据装配器签名：fn(connection, patient_row) -> JSON 可序列化数据。
SectionLoader = Callable[[Any, Any], Any]


class EmergencyAccessService:
    """申请、批准、读取、撤销与事后复核的用例边界。"""

    def __init__(self, database: Database, clock, section_loaders: dict[str, SectionLoader]):
        self.db = database
        self.clock = clock
        self._section_loaders = section_loaders

    # ---- 申请 -----------------------------------------------------------

    def request_access(self, clinic_id: str, actor_id: str, patient_clinic_id: str, patient_id: str,
                       clinical_reason: str, sections: list[str], idempotency_key: str,
                       *, lifetime_minutes: int = 60) -> dict[str, Any]:
        patient_clinic_id = require_id(patient_clinic_id, "患者所属诊所编号")
        patient_id = require_id(patient_id, "患者编号")
        clinical_reason = text(clinical_reason, "临床处置原因", minimum=10, maximum=1000)
        sections = self._normalize_sections(sections)
        key = require_idempotency_key(idempotency_key)
        if not isinstance(lifetime_minutes, int) or isinstance(lifetime_minutes, bool) \
                or not MIN_MINUTES <= lifetime_minutes <= MAX_MINUTES:
            raise ValidationError(f"访问时长必须为 {MIN_MINUTES} 至 {MAX_MINUTES} 分钟")
        request = {"clinic_id": clinic_id, "applicant_id": actor_id,
                   "patient_clinic_id": patient_clinic_id, "patient_id": patient_id,
                   "clinical_reason": clinical_reason, "sections": sections,
                   "lifetime_minutes": lifetime_minutes}
        request_hash = hashlib.sha256(encode_json(request).encode("utf-8")).hexdigest()
        now = timestamp(self.clock.now())
        request_id = new_id("emg")
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "emergency:request", clinic_id=clinic_id)
            if patient_clinic_id == clinic_id:
                raise ValidationError("紧急访问仅用于非本诊所建立的记录；本诊所患者按常规授权读取")
            patient = connection.execute(
                "SELECT id,state FROM patients WHERE id=? AND clinic_id=?", (patient_id, patient_clinic_id)
            ).fetchone()
            if patient is None:
                # 不向外诊所人员确认或否认患者是否存在。
                raise NotFound("患者不存在")
            old = connection.execute(
                "SELECT * FROM emergency_access_requests WHERE clinic_id=? AND idempotency_key=?",
                (clinic_id, key)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise Conflict("紧急访问幂等编号已用于其他请求")
                # 重放只返回既有申请，绝不延长或重新激活旧授权；已到期则收敛为终态。
                if old["state"] == "granted" and old["expires_at"] and old["expires_at"] <= now:
                    connection.execute(
                        "UPDATE emergency_access_requests SET state='expired',version=version+1 WHERE id=?",
                        (old["id"],))
                    audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                                       aggregate_type="emergency_access", aggregate_id=old["id"],
                                       action="emergency.expired", occurred_at=now,
                                       payload={"expires_at": old["expires_at"], "replayed": True})
                    old = connection.execute(
                        "SELECT * FROM emergency_access_requests WHERE id=?", (old["id"],)).fetchone()
                return self._result(old, replayed=True)
            connection.execute(
                "INSERT INTO emergency_access_requests(id,clinic_id,applicant_id,patient_id,patient_clinic_id,"
                "clinical_reason,sections_json,requested_minutes,state,idempotency_key,request_hash,requested_at) "
                "VALUES(?,?,?,?,?,?,?,?, 'requested',?,?,?)",
                (request_id, clinic_id, actor_id, patient_id, patient_clinic_id,
                 clinical_reason, encode_json(sections), lifetime_minutes, key, request_hash, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=request_id,
                               action="emergency.requested", occurred_at=now,
                               payload={"patient_clinic_id": patient_clinic_id, "patient_id": patient_id,
                                        "clinical_reason": clinical_reason, "sections": sections,
                                        "requested_minutes": lifetime_minutes, "request_hash": request_hash})
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone()
            return self._result(row, replayed=False)

    # ---- 批准 / 拒绝 ----------------------------------------------------

    def decide(self, clinic_id: str, actor_id: str, request_id: str, approved: bool,
               *, note: str | None = None, granted_sections: list[str] | None = None) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急访问申请编号")
        if not isinstance(approved, bool):
            raise ValidationError("批准结论必须为布尔值")
        if approved:
            note = text(note or "值班临床负责人批准紧急访问", "批准说明", minimum=0, maximum=1000)
        else:
            note = text(note or "", "拒绝原因", minimum=5, maximum=1000)
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "emergency:decide", clinic_id=clinic_id)
            if principal.role not in CLINICAL_ROLES:
                raise Forbidden("只有值班临床负责人（医生或诊所负责人）可以批准紧急访问")
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?",
                                     (request_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("紧急访问申请不存在")
            if row["state"] != "requested":
                raise Conflict("该申请已有结论，不能重复决定", details={"state": row["state"]})
            # 职责分离：申请人与批准人不能是同一人。
            if row["applicant_id"] == actor_id:
                raise Forbidden("申请人不能批准自己的紧急访问申请")
            applicant = connection.execute(
                "SELECT active FROM staff WHERE id=? AND clinic_id=?", (row["applicant_id"], clinic_id)
            ).fetchone()
            if applicant is None or not applicant["active"]:
                raise Conflict("申请人账号已停用，申请不能再授予访问")
            requested_sections = decode_json(row["sections_json"])
            granted = self._normalize_sections(granted_sections) if granted_sections is not None \
                else requested_sections
            if not set(granted) <= set(requested_sections):
                raise ValidationError("授予范围不能超出申请的资料章节")
            if approved:
                expires_at = timestamp(parsed_timestamp(now) + timedelta(minutes=row["requested_minutes"]))
                connection.execute(
                    "UPDATE emergency_access_requests SET state='granted',decided_by=?,decided_at=?,"
                    "decision_note=?,expires_at=?,granted_sections_json=?,version=version+1 WHERE id=?",
                    (actor_id, now, note, expires_at, encode_json(granted), request_id))
                action, payload = "emergency.granted", {
                    "granted_sections": granted, "expires_at": expires_at,
                    "requested_minutes": row["requested_minutes"], "note": note}
            else:
                connection.execute(
                    "UPDATE emergency_access_requests SET state='denied',decided_by=?,decided_at=?,"
                    "decision_note=?,version=version+1 WHERE id=?",
                    (actor_id, now, note, request_id))
                action, payload = "emergency.denied", {"reason": note, "requested_sections": requested_sections}
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=request_id,
                               action=action, occurred_at=now, payload=payload)
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone()
            return self._result(row, replayed=False)

    # ---- 读取 -----------------------------------------------------------

    def read_section(self, clinic_id: str, actor_id: str, request_id: str, section: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急访问申请编号")
        section = choice(section, "资料章节", SECTIONS)
        now = timestamp(self.clock.now())
        read_id = new_id("emr")
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "emergency:request", clinic_id=clinic_id)
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?",
                                     (request_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("紧急访问申请不存在")
            if row["applicant_id"] != actor_id:
                raise Forbidden("只有申请人本人可以使用该紧急访问授权")
            granted_sections = decode_json(row["granted_sections_json"]) if row["granted_sections_json"] else []
            outcome, denial_reason, data = "denied", None, None
            if row["state"] != "granted":
                denial_reason = f"授权状态为 {row['state']}"
            elif row["expires_at"] and row["expires_at"] <= now:
                # 到期立即失效，并把授权收敛为终态。
                connection.execute(
                    "UPDATE emergency_access_requests SET state='expired',version=version+1 WHERE id=? AND state='granted'",
                    (request_id,))
                audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                                   aggregate_type="emergency_access", aggregate_id=request_id,
                                   action="emergency.expired", occurred_at=now,
                                   payload={"expires_at": row["expires_at"]})
                denial_reason = "访问已到期"
            elif section not in granted_sections:
                denial_reason = "章节不在批准授予范围内"
            else:
                applicant = connection.execute(
                    "SELECT active FROM staff WHERE id=? AND clinic_id=?", (actor_id, clinic_id)).fetchone()
                if applicant is None or not applicant["active"]:
                    # 账号停用立即失效：停用事务已联动吊销，这里兜底拒绝。
                    denial_reason = "账号已停用"
                else:
                    patient = connection.execute(
                        "SELECT * FROM patients WHERE id=? AND clinic_id=?",
                        (row["patient_id"], row["patient_clinic_id"])).fetchone()
                    if patient is None:
                        denial_reason = "患者记录不存在"
                    else:
                        outcome = "granted"
                        data = self._section_loaders[section](connection, patient)
            connection.execute(
                "INSERT INTO emergency_access_reads(id,request_id,section,outcome,denial_reason,read_by,read_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (read_id, request_id, section, outcome, denial_reason, actor_id, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=request_id,
                               action="emergency.read_granted" if outcome == "granted" else "emergency.read_denied",
                               occurred_at=now,
                               payload={"section": section, "outcome": outcome, "denial_reason": denial_reason,
                                        "read_id": read_id, "patient_clinic_id": row["patient_clinic_id"],
                                        "patient_id": row["patient_id"]})
        return {"id": read_id, "request_id": request_id, "section": section, "outcome": outcome,
                "denial_reason": denial_reason, "read_at": now, "data": data}

    # ---- 撤销 -----------------------------------------------------------

    def revoke(self, clinic_id: str, actor_id: str, request_id: str, reason: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急访问申请编号")
        reason = text(reason, "撤销原因", minimum=5, maximum=1000)
        now = timestamp(self.clock.now())
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "emergency:revoke", clinic_id=clinic_id)
            if principal.role != "owner":
                raise Forbidden("只有患者安全负责人（诊所负责人）可以撤销紧急访问")
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?",
                                     (request_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("紧急访问申请不存在")
            if row["state"] in {"revoked", "denied", "expired"}:
                raise Conflict("该授权已失效，无需重复撤销", details={"state": row["state"]})
            connection.execute(
                "UPDATE emergency_access_requests SET state='revoked',revoked_by=?,revoked_at=?,"
                "revoke_reason=?,version=version+1 WHERE id=?",
                (actor_id, now, reason, request_id))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=request_id,
                               action="emergency.revoked", occurred_at=now,
                               payload={"previous_state": row["state"], "reason": reason})
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=?", (request_id,)).fetchone()
            return self._result(row, replayed=False)

    def revoke_for_staff(self, connection, clinic_id: str, staff_id: str, now: str) -> int:
        """账号停用时联动吊销其全部生效授权。在停用事务内调用。"""
        rows = connection.execute(
            "SELECT id FROM emergency_access_requests WHERE clinic_id=? AND applicant_id=? AND state='granted'",
            (clinic_id, staff_id)).fetchall()
        for item in rows:
            connection.execute(
                "UPDATE emergency_access_requests SET state='revoked',revoked_at=?,revoke_reason=?,version=version+1 WHERE id=?",
                (now, "申请人账号停用，授权立即失效", item["id"]))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=None, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=item["id"],
                               action="emergency.revoked", occurred_at=now,
                               payload={"previous_state": "granted", "reason": "账号停用", "system": True})
        return len(rows)

    # ---- 事后审计确认 ---------------------------------------------------

    def review(self, clinic_id: str, actor_id: str, request_id: str, conclusion: str, note: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急访问申请编号")
        conclusion = choice(conclusion, "审计结论", {"confirmed", "questioned"})
        note = text(note, "审计说明", minimum=5, maximum=2000)
        now = timestamp(self.clock.now())
        review_id = new_id("emv")
        with self.db.transaction() as connection:
            principal = principal_for(connection, actor_id, clinic_id)
            authorize(principal, "emergency:review", clinic_id=clinic_id)
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?",
                                     (request_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("紧急访问申请不存在")
            # 审计人必须独立于申请人、批准人和撤销人。
            if actor_id in {row["applicant_id"], row["decided_by"], row["revoked_by"]}:
                raise Forbidden("审计确认人不能是申请人、批准人或撤销人")
            if connection.execute(
                "SELECT 1 FROM emergency_access_reviews WHERE request_id=? AND reviewer_id=?",
                (request_id, actor_id)).fetchone():
                raise Conflict("同一审计人不能重复确认同一次紧急访问")
            connection.execute(
                "INSERT INTO emergency_access_reviews(id,request_id,reviewer_id,conclusion,note,reviewed_at) "
                "VALUES(?,?,?,?,?,?)",
                (review_id, request_id, actor_id, conclusion, note, now))
            audit.append_event(connection, clinic_id=clinic_id, actor_id=actor_id, patient_id=None,
                               aggregate_type="emergency_access", aggregate_id=request_id,
                               action="emergency.reviewed", occurred_at=now,
                               payload={"conclusion": conclusion, "note": note, "review_id": review_id})
        return {"id": review_id, "request_id": request_id, "reviewer_id": actor_id,
                "conclusion": conclusion, "note": note, "reviewed_at": now}

    def history(self, clinic_id: str, actor_id: str, request_id: str) -> dict[str, Any]:
        request_id = require_id(request_id, "紧急访问申请编号")
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "emergency:review", clinic_id=clinic_id)
            row = connection.execute("SELECT * FROM emergency_access_requests WHERE id=? AND clinic_id=?",
                                     (request_id, clinic_id)).fetchone()
            if row is None:
                raise NotFound("紧急访问申请不存在")
            reads = connection.execute(
                "SELECT id,section,outcome,denial_reason,read_by,read_at FROM emergency_access_reads "
                "WHERE request_id=? ORDER BY read_at,id", (request_id,)).fetchall()
            reviews = connection.execute(
                "SELECT id,reviewer_id,conclusion,note,reviewed_at FROM emergency_access_reviews "
                "WHERE request_id=? ORDER BY reviewed_at,id", (request_id,)).fetchall()
            return {
                "request": self._result(row, replayed=False),
                "reads": [dict(item) for item in reads],
                "reviews": [dict(item) for item in reviews],
            }

    def list_requests(self, clinic_id: str, actor_id: str, *, state: str | None = None,
                      limit: int = 100) -> dict[str, Any]:
        if not 1 <= limit <= 300:
            raise ValidationError("查询数量必须为 1 至 300")
        if state is not None:
            state = choice(state, "申请状态", {"requested", "granted", "denied", "revoked", "expired"})
        with self.db.transaction(write=False) as connection:
            authorize(principal_for(connection, actor_id, clinic_id), "emergency:review", clinic_id=clinic_id)
            if state:
                rows = connection.execute(
                    "SELECT * FROM emergency_access_requests WHERE clinic_id=? AND state=? ORDER BY requested_at DESC,id LIMIT ?",
                    (clinic_id, state, limit)).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM emergency_access_requests WHERE clinic_id=? ORDER BY requested_at DESC,id LIMIT ?",
                    (clinic_id, limit)).fetchall()
            return {"items": [self._result(item, replayed=False) for item in rows]}

    # ---- 辅助 -----------------------------------------------------------

    @staticmethod
    def _normalize_sections(sections: Any) -> list[str]:
        if not isinstance(sections, list) or not sections:
            raise ValidationError("至少指定一个所需资料章节")
        if len(sections) > len(SECTIONS):
            raise ValidationError("资料章节数量超出限制")
        normalized = [choice(item, "资料章节", SECTIONS) for item in sections]
        selected = sorted(set(normalized))
        if len(selected) != len(normalized):
            raise ValidationError("资料章节不能重复")
        return selected

    @staticmethod
    def _result(row, *, replayed: bool) -> dict[str, Any]:
        return {
            "id": row["id"], "clinic_id": row["clinic_id"], "applicant_id": row["applicant_id"],
            "patient_clinic_id": row["patient_clinic_id"], "patient_id": row["patient_id"],
            "clinical_reason": row["clinical_reason"],
            "requested_sections": decode_json(row["sections_json"]),
            "granted_sections": decode_json(row["granted_sections_json"]) if row["granted_sections_json"] else [],
            "requested_minutes": row["requested_minutes"],
            "state": row["state"], "requested_at": row["requested_at"],
            "decided_by": row["decided_by"], "decided_at": row["decided_at"],
            "decision_note": row["decision_note"], "expires_at": row["expires_at"],
            "revoked_by": row["revoked_by"], "revoked_at": row["revoked_at"],
            "revoke_reason": row["revoke_reason"], "version": row["version"], "replayed": replayed,
        }


# ---- 跨诊所章节装配器 -----------------------------------------------------
# 与导出服务相同的白名单口径：只取临床必要字段，不返回联系方式密文等内部字段。

def _encounters_section(connection, patient) -> list[dict[str, Any]]:
    encounters = connection.execute(
        "SELECT id,appointment_id,state,opened_by,opened_at,signed_by,signed_at,version "
        "FROM encounters WHERE patient_id=? ORDER BY opened_at,id", (patient["id"],)).fetchall()
    result = []
    for encounter in encounters:
        notes = connection.execute(
            "SELECT section,body,author_id,revision,created_at FROM encounter_notes n "
            "WHERE encounter_id=? AND revision=(SELECT MAX(n2.revision) FROM encounter_notes n2 "
            "WHERE n2.encounter_id=n.encounter_id AND n2.section=n.section) ORDER BY section",
            (encounter["id"],)).fetchall()
        result.append({**dict(encounter), "notes": [dict(note) for note in notes]})
    return result


def _clinical_flags_section(connection, patient) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT id,category,severity,detail,state,effective_from,effective_until,reported_by,"
        "reviewed_by,reviewed_at,resolution_reason,version FROM clinical_flags "
        "WHERE patient_id=? ORDER BY effective_from,id", (patient["id"],)).fetchall()
    return [dict(row) for row in rows]


def default_section_loaders() -> dict[str, SectionLoader]:
    from .exports import PatientExportService

    loaders: dict[str, SectionLoader] = {
        name: (lambda section: lambda connection, patient: PatientExportService._section(connection, section, patient))(name)
        for name in ("profile", "consents", "assessments", "plans", "observations",
                     "appointments", "followups", "incidents")
    }
    loaders["encounters"] = _encounters_section
    loaders["clinical_flags"] = _clinical_flags_section
    return loaders
