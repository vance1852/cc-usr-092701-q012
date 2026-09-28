from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from careflow.clock import FrozenClock
from careflow.db import Database
from careflow.errors import Conflict, Forbidden, NotFound, Unauthorized, ValidationError
from careflow.service import Careflow

REASON = "夜间急诊需查阅既往体重与过敏记录以判断用药剂量"


class EmergencyAccessCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "clinic.sqlite3")
        self.clock = FrozenClock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        self.app = Careflow(self.db, self.clock)
        initial = self.app.initialize_clinic("甲门诊", "Asia/Shanghai", "甲负责人", "OwnerPassphrase!2026")
        self.clinic_a = initial["clinic_id"]
        self.owner_a = initial["owner_id"]
        self.nurse = self.app.create_staff(self.clinic_a, "夜班护士", "nurse", actor_id=self.owner_a)["id"]
        self.nurse_b = self.app.create_staff(self.clinic_a, "夜班护士乙", "nurse", actor_id=self.owner_a)["id"]
        self.clinician = self.app.create_staff(self.clinic_a, "值班医生", "clinician", actor_id=self.owner_a)["id"]
        self.clinician_b = self.app.create_staff(self.clinic_a, "值班医生乙", "clinician", actor_id=self.owner_a)["id"]
        self.auditor = self.app.create_staff(self.clinic_a, "审计员", "auditor", actor_id=self.owner_a)["id"]
        # 患者建档在另一家诊所。
        other = self.app.create_clinic("乙门诊", "UTC")
        self.clinic_b = other["id"]
        self.owner_b = self.app.create_staff(self.clinic_b, "乙负责人", "owner")["id"]
        self.patient = self.app.create_patient(self.clinic_b, self.owner_b, "ext-1", "急诊患者")
        self.app.create_assessment(self.clinic_b, self.owner_b, self.patient["id"], "weight",
                                   {"weight_kg": 80.0}, {"sleep": "一般"})

    def tearDown(self):
        self.temp.cleanup()

    def request(self, sections=("profile", "assessments"), key="emg-1", minutes=30, reason=REASON, actor=None):
        return self.app.emergency.request_access(
            self.clinic_a, actor or self.nurse, self.clinic_b, self.patient["id"],
            reason, list(sections), key, lifetime_minutes=minutes)

    def grant(self, request_id, *, by=None, sections=None):
        return self.app.emergency.decide(
            self.clinic_a, by or self.clinician, request_id, True,
            note="同意急诊调阅", granted_sections=list(sections) if sections else None)

    # ---- 申请与诊所边界 -------------------------------------------------

    def test_regular_role_cannot_read_cross_clinic_but_emergency_flow_can(self):
        with self.assertRaises(NotFound):
            self.app.get_patient(self.clinic_a, self.nurse, self.patient["id"])
        request = self.request()
        self.assertEqual(request["state"], "requested")
        self.grant(request["id"])
        read = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "assessments")
        self.assertEqual(read["outcome"], "granted")
        self.assertEqual(len(read["data"]), 1)

    def test_emergency_request_requires_patient_reason_and_sections(self):
        with self.assertRaises(ValidationError):
            self.request(sections=(), key="emg-x1")
        with self.assertRaises(ValidationError):
            self.request(reason="急诊", key="emg-x2")
        with self.assertRaises(ValidationError):
            self.request(minutes=5, key="emg-x3")
        with self.assertRaises(ValidationError):
            self.request(minutes=500, key="emg-x4")

    def test_local_patient_cannot_use_emergency_channel(self):
        coordinator = self.app.create_staff(self.clinic_a, "协调员", "coordinator", actor_id=self.owner_a)["id"]
        local = self.app.create_patient(self.clinic_a, coordinator, "local-1", "本诊患者")["id"]
        with self.assertRaises(ValidationError):
            self.app.emergency.request_access(
                self.clinic_a, self.nurse, self.clinic_a, local,
                "试图对本诊所患者发起紧急访问调阅", ["profile"], "emg-local")

    def test_only_night_clinical_roles_may_request(self):
        coordinator = self.app.create_staff(self.clinic_a, "协调员", "coordinator", actor_id=self.owner_a)["id"]
        with self.assertRaises(Forbidden):
            self.request(actor=coordinator, key="emg-coord")

    def test_unknown_cross_clinic_patient_is_not_disclosed(self):
        with self.assertRaises(NotFound):
            self.app.emergency.request_access(
                self.clinic_a, self.nurse, self.clinic_b, "pat_does_not_exist",
                REASON, ["profile"], "emg-missing")

    # ---- 双人批准 -------------------------------------------------------

    def test_applicant_cannot_approve_own_request(self):
        request = self.request(actor=self.clinician, key="emg-self")
        with self.assertRaises(Forbidden):
            self.app.emergency.decide(self.clinic_a, self.clinician, request["id"], True, note="自我批准")

    def test_non_clinical_leader_cannot_approve(self):
        request = self.request(key="emg-nurse-approve")
        with self.assertRaises(Forbidden):
            self.app.emergency.decide(self.clinic_a, self.nurse_b, request["id"], True)

    def test_decision_is_one_shot(self):
        request = self.request(key="emg-once")
        self.grant(request["id"])
        with self.assertRaises(Conflict):
            self.app.emergency.decide(self.clinic_a, self.clinician_b, request["id"], False, note="另一医生改判")

    def test_denial_is_recorded_with_reason(self):
        request = self.request(key="emg-deny")
        result = self.app.emergency.decide(
            self.clinic_a, self.clinician, request["id"], False, note="不属于急诊必要范围，拒绝调阅")
        self.assertEqual(result["state"], "denied")
        history = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])
        self.assertEqual(history["request"]["decided_by"], self.clinician)
        self.assertTrue(history["request"]["decision_note"])
        denied = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertEqual(denied["outcome"], "denied")
        self.assertIn("denied", denied["denial_reason"])
        self.assertIsNone(denied["data"])

    def test_granted_scope_cannot_exceed_requested_scope(self):
        request = self.request(sections=("profile",), key="emg-scope")
        with self.assertRaises(ValidationError):
            self.grant(request["id"], sections=["profile", "incidents"])
        # 缩小范围允许，申请仍可被正常批准。
        self.grant(request["id"], sections=["profile"])
        self.assertEqual(
            self.app.emergency.history(self.clinic_a, self.auditor, request["id"])["request"]["granted_sections"],
            ["profile"])

    # ---- 读取与留痕 -----------------------------------------------------

    def test_only_applicant_may_consume_grant(self):
        request = self.request(key="emg-owner-read")
        self.grant(request["id"])
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.clinic_a, self.nurse_b, request["id"], "profile")

    def test_read_outside_granted_section_is_denied_and_logged(self):
        request = self.request(sections=("profile", "assessments", "clinical_flags"), key="emg-read-denied")
        self.grant(request["id"], sections=["profile", "assessments"])
        denied = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "clinical_flags")
        self.assertEqual(denied["outcome"], "denied")
        self.assertIsNone(denied["data"])
        granted = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertEqual(granted["outcome"], "granted")
        history = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])
        outcomes = {(row["section"], row["outcome"]) for row in history["reads"]}
        self.assertIn(("clinical_flags", "denied"), outcomes)
        self.assertIn(("profile", "granted"), outcomes)

    def test_clinical_data_never_includes_contact_ciphertext(self):
        request = self.request(sections=("profile",), key="emg-minimize")
        self.grant(request["id"])
        read = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertNotIn("phone_ciphertext", read["data"])

    # ---- 失效：到期、撤销、停用 -----------------------------------------

    def test_access_expires_at_end_of_short_window(self):
        request = self.request(minutes=30, key="emg-expiry")
        result = self.grant(request["id"])
        self.assertEqual(result["expires_at"], "2026-09-27T12:30:00Z")
        self.clock.set(datetime(2026, 9, 27, 12, 30, tzinfo=UTC))
        read = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertEqual(read["outcome"], "denied")
        self.assertEqual(read["denial_reason"], "访问已到期")
        history = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])
        self.assertEqual(history["request"]["state"], "expired")

    def test_patient_safety_owner_revoke_takes_immediate_effect(self):
        request = self.request(key="emg-revoke")
        self.grant(request["id"])
        # 值班医生不能撤销，只有患者安全负责人（owner）可以。
        with self.assertRaises(Forbidden):
            self.app.emergency.revoke(self.clinic_a, self.clinician_b, request["id"], "医生试图撤销授权")
        revoked = self.app.emergency.revoke(self.clinic_a, self.owner_a, request["id"], "患者安全负责人判断无需继续访问")
        self.assertEqual(revoked["state"], "revoked")
        read = self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertEqual(read["outcome"], "denied")
        with self.assertRaises(Conflict):
            self.app.emergency.revoke(self.clinic_a, self.owner_a, request["id"], "对已撤销授权重复撤销一次")

    def test_disabling_account_revokes_active_grants_immediately(self):
        request = self.request(key="emg-disable")
        self.grant(request["id"])
        self.app.disable_staff(self.clinic_a, self.owner_a, self.nurse, 1)
        history = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])
        self.assertEqual(history["request"]["state"], "revoked")
        self.assertIn("停用", history["request"]["revoke_reason"])
        # 停用后其会话凭据也已失效，无法再发起读取。
        with self.assertRaises(Unauthorized):
            self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")

    def test_cannot_grant_when_applicant_already_disabled(self):
        request = self.request(key="emg-disable-before")
        self.app.disable_staff(self.clinic_a, self.owner_a, self.nurse, 1)
        with self.assertRaises((Conflict, Unauthorized)):
            self.grant(request["id"])

    # ---- 重放不延长旧授权 -----------------------------------------------

    def test_replayed_request_never_extends_old_grant(self):
        request = self.request(minutes=30, key="emg-replay")
        self.grant(request["id"])
        before = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])["request"]["expires_at"]
        replay = self.request(minutes=30, key="emg-replay")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["id"], request["id"])
        self.assertEqual(replay["expires_at"], before)
        # 即使窗口已过，重放仍只返回原授权而不续长。
        self.clock.set(datetime(2026, 9, 27, 13, 0, tzinfo=UTC))
        stale = self.request(minutes=30, key="emg-replay")
        self.assertEqual(stale["state"], "expired")
        self.assertEqual(stale["expires_at"], before)
        # 同幂等键不同内容必须被拒绝。
        with self.assertRaises(Conflict):
            self.request(sections=("incidents",), minutes=60, key="emg-replay")
        # 新急诊需要全新申请。
        fresh = self.request(key="emg-replay-fresh")
        self.assertNotEqual(fresh["id"], request["id"])
        self.assertEqual(fresh["state"], "requested")

    # ---- 事后独立审计 ---------------------------------------------------

    def test_reviewer_must_be_independent_and_is_append_only(self):
        request = self.request(key="emg-review")
        self.grant(request["id"])
        self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        # 申请人与批准人都不能审计。
        with self.assertRaises(Forbidden):
            self.app.emergency.review(self.clinic_a, self.nurse, request["id"], "confirmed", "申请人自审无效")
        with self.assertRaises(Forbidden):
            self.app.emergency.review(self.clinic_a, self.clinician, request["id"], "confirmed", "批准人自审无效")
        review = self.app.emergency.review(
            self.clinic_a, self.auditor, request["id"], "confirmed", "调阅理由与范围相符，读取章节均在授权内")
        self.assertEqual(review["conclusion"], "confirmed")
        # 同一审计人不能重复确认。
        with self.assertRaises(Conflict):
            self.app.emergency.review(self.clinic_a, self.auditor, request["id"], "questioned", "审计员对同一访问重复确认一次")
        # 审计人不能借审查调阅病历本身。
        with self.assertRaises((Forbidden, NotFound)):
            self.app.emergency.read_section(self.clinic_a, self.auditor, request["id"], "profile")

    def test_questioned_review_supported_and_visible_in_history(self):
        request = self.request(sections=("profile", "incidents"), key="emg-question")
        self.grant(request["id"])
        self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "incidents")
        self.app.emergency.review(self.clinic_a, self.auditor, request["id"], "questioned",
                                  "临床原因陈述与实际读取章节不完全匹配，需跟进")
        history = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])
        self.assertEqual(history["reviews"][0]["conclusion"], "questioned")

    def test_owner_without_participation_may_review_but_revoker_is_excluded(self):
        # owner 未参与申请与批准时可作为独立复核人。
        request = self.request(key="emg-owner-review")
        self.grant(request["id"])
        review = self.app.emergency.review(
            self.clinic_a, self.owner_a, request["id"], "confirmed", "负责人事后核对依据与范围均合规")
        self.assertEqual(review["reviewer_id"], self.owner_a)

    def test_revoker_cannot_review_own_revocation(self):
        request = self.request(key="emg-revoke-review")
        self.grant(request["id"])
        self.app.emergency.revoke(self.clinic_a, self.owner_a, request["id"], "患者安全负责人撤销该紧急访问")
        with self.assertRaises(Forbidden):
            self.app.emergency.review(
                self.clinic_a, self.owner_a, request["id"], "confirmed", "撤销人试图自行确认该次访问")

    def test_audit_listing_and_history_require_reviewer_permission(self):
        request = self.request(key="emg-listing")
        self.grant(request["id"])
        with self.assertRaises(Forbidden):
            self.app.emergency.history(self.clinic_a, self.nurse, request["id"])
        with self.assertRaises(Forbidden):
            self.app.emergency.list_requests(self.clinic_a, self.clinician)
        listing = self.app.emergency.list_requests(self.clinic_a, self.auditor)
        self.assertTrue(any(item["id"] == request["id"] for item in listing["items"]))

    # ---- 不可变轨迹 -----------------------------------------------------

    def test_lifecycle_events_enter_hash_chain_and_tampering_is_detected(self):
        request = self.request(key="emg-chain")
        self.grant(request["id"])
        self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.app.emergency.review(self.clinic_a, self.auditor, request["id"], "confirmed", "调阅依据与范围相符，确认合规")
        events = self.app.audit_history(self.clinic_a, self.owner_a, limit=500)
        actions = {event["action"] for event in events if event["aggregate_id"] == request["id"]}
        self.assertEqual(
            actions,
            {"emergency.requested", "emergency.granted", "emergency.read_granted", "emergency.reviewed"})
        self.assertTrue(self.app.verify_audit(self.clinic_a, self.owner_a)["ok"])
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE audit_events SET action='emergency.deleted' WHERE aggregate_id=? AND action='emergency.requested'",
                (request["id"],))
        self.assertFalse(self.app.verify_audit(self.clinic_a, self.owner_a)["ok"])

    def test_grant_then_expiry_records_basis_scope_expiry_in_trail(self):
        request = self.request(sections=("profile", "assessments"), minutes=15, key="emg-fields")
        self.grant(request["id"], sections=["assessments"])
        self.clock.set(datetime(2026, 9, 27, 12, 16, tzinfo=UTC))
        self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "assessments")
        record = self.app.emergency.history(self.clinic_a, self.auditor, request["id"])["request"]
        self.assertEqual(record["clinical_reason"], REASON)            # 申请依据
        self.assertEqual(record["granted_sections"], ["assessments"])  # 授予范围
        self.assertEqual(record["expires_at"], "2026-09-27T12:15:00Z")  # 到期
        self.assertEqual(record["state"], "expired")                   # 到期原因（终态）

    # ---- 巡检：事后独立复核闭环 -----------------------------------------

    def _finding_ids(self, code):
        report = self.app.run_diagnostics(self.clinic_a, self.owner_a)
        return {f["aggregate_id"] for f in report["findings"] if f["code"] == code}

    def test_diagnostics_flags_finished_access_without_independent_review(self):
        denied_request = self.request(key="emg-diag-deny")
        self.app.emergency.decide(self.clinic_a, self.clinician, denied_request["id"], False,
                                  note="理由不构成急诊必要情形，拒绝调阅")
        granted_request = self.request(minutes=30, key="emg-diag-expire")
        self.grant(granted_request["id"])
        self.app.emergency.read_section(self.clinic_a, self.nurse, granted_request["id"], "profile")
        # 仍在生效窗口内的授权不应被标记为待复核。
        active_request = self.request(minutes=120, key="emg-diag-active")
        self.grant(active_request["id"])

        self.clock.set(datetime(2026, 9, 27, 13, 0, tzinfo=UTC))
        pending = self._finding_ids("emergency_access.requires_review")
        self.assertIn(denied_request["id"], pending)
        self.assertIn(granted_request["id"], pending)
        self.assertNotIn(active_request["id"], pending)

        # 独立审计确认后该项消失。
        self.app.emergency.review(self.clinic_a, self.auditor, granted_request["id"],
                                  "confirmed", "依据范围与读取章节相符，确认合规")
        pending = self._finding_ids("emergency_access.requires_review")
        self.assertNotIn(granted_request["id"], pending)
        self.assertIn(denied_request["id"], pending)

    def test_diagnostics_flags_grant_past_expiry_until_closed(self):
        request = self.request(minutes=30, key="emg-diag-stale")
        self.grant(request["id"])
        self.clock.set(datetime(2026, 9, 27, 13, 0, tzinfo=UTC))
        self.assertIn(request["id"], self._finding_ids("emergency_access.expiry_not_closed"))
        # 下一次读取即时收敛，提示消失并转入待复核。
        self.app.emergency.read_section(self.clinic_a, self.nurse, request["id"], "profile")
        self.assertNotIn(request["id"], self._finding_ids("emergency_access.expiry_not_closed"))
        self.assertIn(request["id"], self._finding_ids("emergency_access.requires_review"))


if __name__ == "__main__":
    unittest.main()
