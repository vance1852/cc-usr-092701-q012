from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from careflow.api import create_handler
from careflow.clock import FrozenClock
from careflow.db import Database
from careflow.errors import Conflict, Forbidden, NotFound, Unauthorized, ValidationError
from careflow.service import Careflow


class CareflowCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "clinic.sqlite3")
        self.clock = FrozenClock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        self.app = Careflow(self.db, self.clock)
        initial = self.app.initialize_clinic("澄序门诊", "Asia/Shanghai", "诊所负责人", "LongPassphrase!2026")
        self.clinic = initial["clinic_id"]
        self.owner = initial["owner_id"]
        self.clinician = self.app.create_staff(self.clinic, "临床医生", "clinician", actor_id=self.owner)["id"]
        self.nurse = self.app.create_staff(self.clinic, "护理人员", "nurse", actor_id=self.owner)["id"]
        self.coordinator = self.app.create_staff(self.clinic, "运营协调员", "coordinator", actor_id=self.owner)["id"]
        self.patient = self.app.create_patient(self.clinic, self.coordinator, "case-017", "林女士")

    def tearDown(self):
        self.temp.cleanup()

    def consent(self, purpose="weight_program", revision=1, expires_at=None):
        digest = hashlib.sha256(f"{purpose}-r{revision}".encode()).hexdigest()
        return self.app.grant_consent(self.clinic, self.clinician, self.patient["id"], purpose,
                                      revision, digest, expires_at=expires_at)

    def plan(self, kind="weight"):
        consent = self.consent("weight_program" if kind == "weight" else "aesthetic_procedure")
        return self.app.create_plan(
            self.clinic, self.clinician, self.patient["id"], kind, self.clinician,
            {"description": "按门诊约定复核", "review_interval_days": 30},
            {"screening": "reviewed", "contraindications": [], "review_required": False},
            "2026-09-27", target_date="2026-12-27", consent_id=consent["id"])

    def appointment(self, key="visit-1"):
        return self.app.create_appointment(
            self.clinic, self.coordinator, self.patient["id"], "复诊",
            "2026-09-29T10:00:00+08:00", "2026-09-29T10:30:00+08:00", key, staff_id=self.clinician)

    def test_initialization_is_atomic_and_password_change_revokes_sessions(self):
        self.assertEqual(self.app.login(self.clinic, self.owner, "LongPassphrase!2026")["role"], "owner")
        token = self.app.login(self.clinic, self.owner, "LongPassphrase!2026")["access_token"]
        with self.assertRaises(Conflict):
            self.app.initialize_clinic("另一诊所", "UTC", "第二负责人", "AnotherPassphrase!2026")
        self.app.set_password(self.clinic, self.owner, self.owner, "NewPassphrase!2026")
        with self.assertRaises(Unauthorized):
            self.app.staff_for_token(self.clinic, token)
        self.assertTrue(self.app.login(self.clinic, self.owner, "NewPassphrase!2026")["access_token"])

    def test_clinic_boundary_and_role_permissions_hide_cross_clinic_records(self):
        other = self.app.create_clinic("另一诊所", "UTC")
        outsider = self.app.create_staff(other["id"], "负责人", "owner")
        with self.assertRaises(Unauthorized):
            self.app.get_patient(self.clinic, outsider["id"], self.patient["id"])
        with self.assertRaises(Forbidden):
            self.app.grant_consent(self.clinic, self.coordinator, self.patient["id"], "weight_program", 1, "a" * 64)
        self.assertNotIn("phone_ciphertext", self.app.get_patient(self.clinic, self.coordinator, self.patient["id"]))

    def test_withdrawal_preserves_consent_history_and_pauses_dependent_plan(self):
        plan = self.plan()
        self.app.transition_plan(self.clinic, self.clinician, plan["id"], 1, "propose")
        self.app.transition_plan(self.clinic, self.clinician, plan["id"], 2, "activate")
        consent = self.app.consent_history(self.clinic, self.clinician, self.patient["id"])[0]
        result = self.app.withdraw_consent(self.clinic, self.clinician, consent["id"], "患者提出撤回")
        self.assertEqual(result["state"], "withdrawn")
        self.assertEqual(self.app.plan_history(self.clinic, self.clinician, plan["id"])[-1]["snapshot"]["state"], "paused")
        self.assertEqual(len(self.app.consent_history(self.clinic, self.clinician, self.patient["id"])), 1)
        self.assertTrue(self.app.withdraw_consent(self.clinic, self.clinician, consent["id"], "重复请求")["replayed"])

    def test_plan_requires_signed_assessment_and_versioned_consent(self):
        consent = self.consent()
        assessment = self.app.create_assessment(self.clinic, self.clinician, self.patient["id"], "weight",
                                                {"weight_kg": "72.5", "waist_cm": 83}, {"sleep": "一般"})
        with self.assertRaises(Conflict):
            self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                 {"description": "目标"}, {"review_required": True}, "2026-09-27",
                                 consent_id=consent["id"], assessment_id=assessment["id"])
        self.app.sign_assessment(self.clinic, self.clinician, assessment["id"], expected_version=1)
        plan = self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                    {"description": "目标"}, {"review_required": True}, "2026-09-27",
                                    consent_id=consent["id"], assessment_id=assessment["id"])
        self.assertEqual(plan["state"], "draft")
        with self.assertRaises(Conflict):
            self.app.transition_plan(self.clinic, self.clinician, plan["id"], 1, "activate")

    def test_expired_consent_is_not_used_for_new_plan(self):
        consent = self.consent(expires_at="2026-09-27T12:01:00Z")
        self.clock.set(datetime(2026, 9, 27, 12, 2, tzinfo=UTC))
        with self.assertRaises(Conflict):
            self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                 {"description": "目标"}, {}, "2026-09-27", consent_id=consent["id"])

    def test_appointment_hold_is_idempotent_and_expires_at_boundary(self):
        first = self.appointment()
        replay = self.appointment()
        self.assertEqual(first["id"], replay["id"])
        self.assertTrue(replay["replayed"])
        with self.assertRaises(Conflict):
            self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                        "2026-09-29T10:00:00+08:00", "2026-09-29T10:30:00+08:00", "visit-1",
                                        staff_id=self.clinician, plan_id="different")
        self.clock.set(datetime(2026, 9, 27, 12, 10, tzinfo=UTC))
        self.assertEqual(self.app.expire_holds(self.clinic)["expired"], 1)
        with self.assertRaises(Conflict):
            self.app.transition_appointment(self.clinic, self.coordinator, first["id"], 2, "book")

    def test_staff_overlap_is_rejected_but_adjacent_time_is_allowed(self):
        self.appointment("morning")
        with self.assertRaises(Conflict):
            self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                        "2026-09-29T10:15:00+08:00", "2026-09-29T10:45:00+08:00", "overlap",
                                        staff_id=self.clinician)
        adjacent = self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                              "2026-09-29T10:30:00+08:00", "2026-09-29T11:00:00+08:00", "adjacent",
                                              staff_id=self.clinician)
        self.assertEqual(adjacent["state"], "held")

    def test_observation_correction_is_append_only_and_report_uses_effective_value(self):
        original = self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 73.2,
                                              "2026-09-27T08:00:00+08:00")
        correction = self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 72.8,
                                                 "2026-09-27T08:00:00+08:00", correction_of=original["id"])
        series = self.app.reports.weight_series(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual([row["weight_kg"] for row in series["observations"]], [72.8])
        self.assertEqual(correction["correction_of"], original["id"])
        with self.assertRaises(Conflict):
            self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 72.1,
                                         "2026-09-27T08:00:00+08:00", correction_of=original["id"])

    def test_followup_lease_fencing_prevents_late_completion(self):
        followup = self.app.schedule_followup(self.clinic, self.clinician, self.patient["id"],
                                              "2026-09-27T11:00:00Z", "复诊反馈", "fup-1")
        first = self.app.claim_followups(self.clinic, self.nurse, lease_minutes=1)[0]
        self.clock.set(datetime(2026, 9, 27, 12, 2, tzinfo=UTC))
        second = self.app.claim_followups(self.clinic, self.coordinator, lease_minutes=3)[0]
        with self.assertRaises(Conflict):
            self.app.complete_followup(self.clinic, self.nurse, followup["id"], first["claim_token"], "迟到回写", first["version"])
        done = self.app.complete_followup(self.clinic, self.coordinator, followup["id"], second["claim_token"], "已联系", second["version"])
        self.assertEqual(done["state"], "done")

    def test_incident_history_is_versioned_and_replay_does_not_duplicate(self):
        incident = self.app.report_incident(self.clinic, self.nurse, self.patient["id"], "术后不适", "moderate",
                                            "2026-09-27T10:00:00+08:00", "患者报告局部红肿", "incident-1")
        replay = self.app.report_incident(self.clinic, self.nurse, self.patient["id"], "术后不适", "moderate",
                                          "2026-09-27T10:00:00+08:00", "患者报告局部红肿", "incident-1")
        self.assertEqual(replay["id"], incident["id"])
        self.app.transition_incident(self.clinic, self.clinician, incident["id"], "triage", "安排临床评估", 1)
        history = self.app.incident_history(self.clinic, self.clinician, incident["id"])
        self.assertEqual([item["type"] for item in history["events"]], ["reported", "triage"])

    def test_stop_flag_requires_clinician_review_and_diagnostic_reports_it(self):
        flag = self.app.clinical_flags.report(self.clinic, self.nurse, self.patient["id"], "prior_reaction", "stop", "既往材料待核实")
        report = self.app.run_diagnostics(self.clinic, self.owner)
        self.assertIn("clinical_flag.requires_review", {item["code"] for item in report["findings"]})
        with self.assertRaises(Forbidden):
            self.app.clinical_flags.review(self.clinic, self.nurse, flag["id"], 1, "confirm", "已核实")
        self.app.clinical_flags.review(self.clinic, self.clinician, flag["id"], 1, "confirm", "已复核原始材料")
        flags = self.app.clinical_flags.list_for_patient(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(flags[0]["state"], "confirmed")

    def test_encounter_requires_sections_and_amendment_preserves_signed_note(self):
        appointment = self.appointment()
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 1, "book")
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 2, "arrive")
        self.clock.set(datetime(2026, 9, 29, 2, 0, tzinfo=UTC))
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 3, "start")
        encounter = self.app.encounter_for_appointment(self.clinic, self.clinician, appointment["id"])
        with self.assertRaises(Conflict):
            self.app.sign_encounter(self.clinic, self.clinician, encounter["id"], 1)
        for section in ("chief_complaint", "assessment", "plan"):
            self.app.add_encounter_note(self.clinic, self.clinician, encounter["id"], section, f"记录-{section}",
                                        expected_version=encounter["version"])
            encounter = self.app.encounter_for_appointment(self.clinic, self.clinician, appointment["id"])
        self.app.sign_encounter(self.clinic, self.clinician, encounter["id"], encounter["version"])
        signed = self.app.encounter_notes(self.clinic, self.clinician, encounter["id"])
        first = next(item for item in signed["notes"] if item["section"] == "assessment")
        amended = self.app.add_encounter_note(self.clinic, self.clinician, encounter["id"], "assessment", "补充记录",
                                              expected_version=signed["version"], amendment_reason="补充化验时间")
        self.assertEqual(amended["state"], "amended")
        history = self.app.encounter_notes(self.clinic, self.clinician, encounter["id"])["notes"]
        self.assertTrue(any(item["id"] == first["id"] for item in history))

    def test_stock_uses_fefo_and_quarantine_blocks_consumption(self):
        product = self.app.supplies.register_product(self.clinic, self.owner, "无菌敷料", "consumable", "片")
        later = self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-1", "batch-later", 8,
                                              "receive-1", expires_on="2027-06-01")
        earlier = self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-1", "batch-earlier", 5,
                                                "receive-2", expires_on="2027-01-01")
        appointment = self.appointment()
        reserved = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 7, "stock-reserve-1")
        self.assertEqual([row["lot_id"] for row in reserved["reservations"]], [earlier["id"], later["id"]])
        self.app.supplies.change_lot_state(self.clinic, self.owner, later["id"], "recall", "批次通知召回")
        with self.assertRaises(Conflict):
            self.app.supplies.consume_reservation(self.clinic, self.clinician, reserved["reservations"][1]["id"], expected_version=1)

    def test_stock_reservation_is_all_or_nothing_and_same_request_replays(self):
        product = self.app.supplies.register_product(self.clinic, self.owner, "一次性导管", "consumable", "支")
        self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-2", "lot-a", 2, "receive-a")
        appointment = self.appointment()
        with self.assertRaises(Conflict):
            self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 3, "reserve-too-many")
        balance = self.app.supplies.lot_balances(self.clinic, product["id"])[0]
        self.assertEqual(balance["available_quantity"], 2)
        first = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 1, "reserve-one")
        replay = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 1, "reserve-one")
        self.assertEqual(first["reservations"], replay["reservations"])
        self.assertTrue(replay["replayed"])

    def test_milestone_defer_history_and_idempotent_creation(self):
        plan = self.plan()
        first = self.app.milestones.create(self.clinic, self.clinician, plan["id"], "review", "复核体重记录",
                                           "2026-10-10T09:00:00+08:00", "mile-1", assigned_to=self.nurse)
        again = self.app.milestones.create(self.clinic, self.clinician, plan["id"], "review", "复核体重记录",
                                           "2026-10-10T09:00:00+08:00", "mile-1", assigned_to=self.nurse)
        self.assertEqual(first["id"], again["id"])
        deferred = self.app.milestones.transition(self.clinic, self.nurse, first["id"], 1, "defer",
                                                 reason="患者改期", new_due_at="2026-10-12T09:00:00+08:00")
        self.assertEqual(deferred["state"], "pending")
        self.assertEqual(len(self.app.milestones.history(self.clinic, self.clinician, first["id"])), 2)

    def test_export_needs_consent_is_minimized_and_idempotent(self):
        with self.assertRaises(Conflict):
            self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["profile"], "患者本人申请", "export-1")
        self.consent("data_export")
        first = self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["profile", "observations"], "患者本人申请", "export-1")
        replay = self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["observations", "profile"], "患者本人申请", "export-1")
        self.assertEqual(first["sha256"], replay["sha256"])
        self.assertTrue(replay["replayed"])
        self.assertNotIn("phone_ciphertext", json.dumps(first, ensure_ascii=False))

    def test_daily_report_uses_clinic_calendar_day_and_dst_aware_bounds(self):
        clinic = self.app.create_clinic("北美诊所", "America/New_York")
        owner = self.app.create_staff(clinic["id"], "负责人", "owner")
        self.assertEqual(self.app.reports.daily_operations(clinic["id"], owner["id"], "2026-11-01")["window"]["ends_at"],
                         "2026-11-02T05:00:00Z")

    def test_audit_hash_chain_detects_tampering(self):
        self.app.audit_history(self.clinic, self.owner)
        self.assertTrue(self.app.verify_audit(self.clinic, self.owner)["ok"])
        with self.db.transaction() as connection:
            connection.execute("UPDATE audit_events SET action='tampered' WHERE sequence=1")
        self.assertFalse(self.app.verify_audit(self.clinic, self.owner)["ok"])

    def test_http_login_patient_creation_and_validation_error(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            request = Request(base + "/auth/token", data=json.dumps({"staff_id": self.owner,
                            "password": "LongPassphrase!2026"}).encode(), method="POST",
                              headers={"X-Clinic-ID": self.clinic, "Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                token = json.loads(response.read())["access_token"]
                self.assertEqual(response.status, 201)
            request = Request(base + "/patients", data=json.dumps({"external_ref": "http-1", "name": "周女士"}).encode(),
                              method="POST", headers={"X-Clinic-ID": self.clinic, "Authorization": f"Bearer {token}",
                                                       "Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                patient = json.loads(response.read())
                self.assertEqual(response.status, 201)
            request = Request(base + f"/patients/{patient['id']}", headers={"X-Clinic-ID": self.clinic,
                              "Authorization": "Bearer invalid"})
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class EmergencyAccessCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "clinic.sqlite3")
        self.clock = FrozenClock(datetime(2026, 9, 28, 0, 0, tzinfo=UTC))
        self.app = Careflow(self.db, self.clock)
        initial = self.app.initialize_clinic("澄序门诊", "Asia/Shanghai", "诊所负责人", "LongPassphrase!2026")
        self.home = initial["clinic_id"]
        self.owner = initial["owner_id"]
        self.clinician = self.app.create_staff(self.home, "值班医生甲", "clinician", actor_id=self.owner)["id"]
        self.clinician_b = self.app.create_staff(self.home, "值班医生乙", "clinician", actor_id=self.owner)["id"]
        self.nurse = self.app.create_staff(self.home, "夜班护士", "nurse", actor_id=self.owner)["id"]
        self.coordinator = self.app.create_staff(self.home, "夜间协调员", "coordinator", actor_id=self.owner)["id"]
        self.auditor = self.app.create_staff(self.home, "独立审计员", "auditor", actor_id=self.owner)["id"]
        source = self.app.create_clinic("兄弟门诊", "UTC")
        self.source = source["id"]
        self.source_owner = self.app.create_staff(self.source, "外诊所负责人", "owner")["id"]
        self.source_patient = self.app.create_patient(self.source, self.source_owner, "ext-9", "急诊患者")

    def tearDown(self):
        self.temp.cleanup()

    def reason(self):
        return "夜间急诊处置，需核实患者在外诊所的过敏史与既往评估"

    def request(self, requester=None, sections=None, ttl=60, key="emg-1"):
        return self.app.emergency.request_access(
            self.home, requester or self.nurse, self.source, self.source_patient["id"],
            self.reason(), sections or ["profile", "assessments", "clinical_flags"], ttl, key)

    def approve(self, request, approver=None, **kwargs):
        return self.app.emergency.decide(
            self.home, approver or self.clinician, request["id"], "approve",
            expected_version=request["version"], **kwargs)

    def test_full_flow_grants_short_lived_cross_clinic_read_with_trails(self):
        request = self.request()
        self.assertEqual(request["state"], "requested")
        granted = self.approve(request)
        self.assertEqual(granted["state"], "active")
        self.assertEqual(granted["granted_sections"], ["assessments", "clinical_flags", "profile"])
        result = self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        self.assertEqual(result["data"]["display_name"], "急诊患者")
        self.assertEqual(result["source_clinic_id"], self.source)
        detail = self.app.emergency.request_detail(self.home, self.auditor, request["id"])
        self.assertEqual([read["section"] for read in detail["reads"]], ["profile"])
        actions = {event["action"] for event in self.app.audit_history(self.home, self.owner)}
        self.assertIn("emergency.requested", actions)
        self.assertIn("emergency.approved", actions)
        self.assertIn("emergency.section_read", actions)
        # 来源诊所链同步镜像披露事件，操作人在载荷中归属。
        mirrored = self.app.audit_history(self.source, self.source_owner)
        self.assertTrue(any(event["action"] == "emergency.section_read" for event in mirrored))
        self.assertTrue(self.app.verify_audit(self.home, self.owner)["ok"])
        self.assertTrue(self.app.verify_audit(self.source, self.source_owner)["ok"])

    def test_requestor_cannot_approve_and_non_clinical_roles_cannot_decide(self):
        own = self.request(requester=self.clinician, key="emg-self")
        with self.assertRaises(Forbidden):
            self.approve(own, approver=self.clinician)
        other = self.request(key="emg-other")
        with self.assertRaises(Forbidden):
            self.app.emergency.decide(self.home, self.nurse, other["id"], "approve", expected_version=1)
        with self.assertRaises(Forbidden):
            self.app.emergency.decide(self.home, self.coordinator, other["id"], "approve", expected_version=1)
        with self.assertRaises(Forbidden):
            self.app.emergency.decide(self.home, self.auditor, other["id"], "approve", expected_version=1)

    def test_approval_can_only_narrow_scope_and_duration(self):
        request = self.request(sections=["profile", "plans"], ttl=60)
        with self.assertRaises(ValidationError):
            self.approve(request, granted_sections=["profile", "incidents"])
        with self.assertRaises(ValidationError):
            self.approve(request, granted_ttl_minutes=90)
        granted = self.approve(request, granted_sections=["profile"], granted_ttl_minutes=15)
        self.assertEqual(granted["granted_sections"], ["profile"])
        self.assertEqual(granted["granted_ttl_minutes"], 15)
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.home, self.nurse, request["id"], "plans")
        # 超范围的被拒绝读取也留痕。
        actions = [event["action"] for event in self.app.audit_history(self.home, self.owner)]
        self.assertIn("emergency.read_denied", actions)

    def test_denial_requires_reason_and_blocks_access(self):
        request = self.request(key="emg-deny")
        with self.assertRaises(ValidationError):
            self.app.emergency.decide(self.home, self.clinician, request["id"], "deny",
                                     expected_version=1, note="")
        denied = self.app.emergency.decide(self.home, self.clinician, request["id"], "deny",
                                          expected_version=1, note="与夜间急诊处置无关")
        self.assertEqual(denied["state"], "denied")
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        with self.assertRaises(Conflict):
            self.app.emergency.decide(self.home, self.clinician_b, request["id"], "approve",
                                     expected_version=2)

    def test_access_expires_and_sweep_marks_it(self):
        request = self.request(ttl=5, key="emg-expiry")
        self.approve(request)
        self.clock.set(datetime(2026, 9, 28, 0, 6, tzinfo=UTC))
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        detail = self.app.emergency.request_detail(self.home, self.auditor, request["id"])
        self.assertEqual(detail["state"], "expired")
        self.assertEqual(detail["reads"], [])
        actions = [event["action"] for event in self.app.audit_history(self.home, self.owner)]
        self.assertIn("emergency.expired", actions)
        self.assertIn("emergency.read_denied", actions)

        second = self.request(ttl=5, key="emg-sweep")
        self.approve(second, approver=self.clinician_b)
        self.clock.set(datetime(2026, 9, 28, 0, 12, tzinfo=UTC))
        swept = self.app.emergency.sweep_expired(self.home, self.auditor)
        self.assertEqual(swept["expired"], 1)
        self.assertEqual(self.app.emergency.request_detail(self.home, self.auditor, second["id"])["state"], "expired")

    def test_safety_owner_revocation_takes_effect_immediately(self):
        request = self.request(key="emg-revoke")
        self.approve(request)
        self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        with self.assertRaises(Forbidden):
            self.app.emergency.revoke(self.home, self.clinician, request["id"], "临床岗位无权撤销")
        revoked = self.app.emergency.revoke(self.home, self.owner, request["id"], "患者安全负责人要求中止访问",
                                            expected_version=2)
        self.assertEqual(revoked["state"], "revoked")
        self.assertEqual(revoked["revoked_by"], self.owner)
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        with self.assertRaises(Conflict):
            self.app.emergency.revoke(self.home, self.owner, request["id"], "不能重复撤销", expected_version=3)

    def test_disabling_account_revokes_pending_and_active_requests(self):
        night = self.app.create_staff(self.home, "另一名夜班护士", "nurse", actor_id=self.owner)["id"]
        pending = self.request(requester=night, key="emg-pending")
        active = self.request(requester=night, key="emg-active")
        self.approve(active, approver=self.clinician_b)
        version = None
        with self.db.transaction(write=False) as connection:
            version = connection.execute("SELECT version FROM staff WHERE id=?", (night,)).fetchone()["version"]
        self.app.disable_staff(self.home, self.owner, night, version)
        self.assertEqual(self.app.emergency.request_detail(self.home, self.auditor, pending["id"])["state"], "revoked")
        detail = self.app.emergency.request_detail(self.home, self.auditor, active["id"])
        self.assertEqual(detail["state"], "revoked")
        self.assertIn("账号停用", detail["revocation_reason"])
        # 停用账号在读取入口即被拒绝（认证与授权双重失效）。
        with self.assertRaises(Unauthorized):
            self.app.emergency.read_section(self.home, night, active["id"], "profile")

    def test_replayed_request_never_extends_grant(self):
        request = self.request(ttl=30, key="emg-replay")
        granted = self.approve(request)
        first_expiry = granted["grant_expires_at"]
        self.clock.set(datetime(2026, 9, 28, 0, 10, tzinfo=UTC))
        replay = self.request(ttl=30, key="emg-replay")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["id"], request["id"])
        self.assertEqual(replay["state"], "active")
        self.assertEqual(replay["version"], 2)
        self.clock.set(datetime(2026, 9, 28, 0, 31, tzinfo=UTC))
        with self.assertRaises(Forbidden):
            self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        with self.assertRaises(Conflict):
            self.request(ttl=60, key="emg-replay")

    def test_revocation_during_read_is_fenced_and_denied_read_is_recorded(self):
        from careflow import emergency_access as emergency_module

        request = self.request(key="emg-race")
        self.approve(request)
        original = emergency_module.PatientExportService._section

        def revoking_section(connection, section, patient):
            # 模拟在读阶段提取数据与写阶段留痕之间，患者安全负责人撤销授权。
            self.app.emergency.revoke(self.home, self.owner, request["id"], "读取进行期间安全负责人撤销",
                                      expected_version=2)
            return original(connection, section, patient)

        emergency_module.PatientExportService._section = staticmethod(revoking_section)
        try:
            with self.assertRaises(Forbidden):
                self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        finally:
            emergency_module.PatientExportService._section = staticmethod(original)
        detail = self.app.emergency.request_detail(self.home, self.auditor, request["id"])
        self.assertEqual(detail["state"], "revoked")
        self.assertEqual(detail["reads"], [])
        actions = [event["action"] for event in self.app.audit_history(self.home, self.owner)]
        self.assertEqual(actions.count("emergency.read_denied"), 1)

    def test_only_independent_auditor_can_confirm_afterwards(self):
        request = self.request(key="emg-review")
        self.approve(request)
        self.app.emergency.read_section(self.home, self.nurse, request["id"], "profile")
        with self.assertRaises(Forbidden):
            self.app.emergency.review(self.home, self.nurse, request["id"], "appropriate", "申请人不能确认")
        with self.assertRaises(Forbidden):
            self.app.emergency.review(self.home, self.clinician, request["id"], "appropriate", "批准人不能确认")
        with self.assertRaises(Forbidden):
            self.app.emergency.review(self.home, self.owner, request["id"], "appropriate", "非审计岗位不能确认")
        review = self.app.emergency.review(self.home, self.auditor, request["id"], "appropriate",
                                          "申请依据充分，读取范围与急诊需要相符")
        self.assertEqual(review["conclusion"], "appropriate")
        with self.assertRaises(Conflict):
            self.app.emergency.review(self.home, self.auditor, request["id"], "appropriate", "同一审计人不能重复确认")
        detail = self.app.emergency.request_detail(self.home, self.auditor, request["id"])
        self.assertEqual([item["reviewer_id"] for item in detail["reviews"]], [self.auditor])

    def test_request_validation_and_visibility_rules(self):
        with self.assertRaises(ValidationError):
            self.app.emergency.request_access(self.home, self.nurse, self.home, self.source_patient["id"],
                                              self.reason(), ["profile"], 30, "emg-x")
        with self.assertRaises(ValidationError):
            self.request(ttl=4, key="emg-short")
        with self.assertRaises(ValidationError):
            self.request(ttl=121, key="emg-long")
        with self.assertRaises(ValidationError):
            self.request(sections=["profile", "profile"], key="emg-dup")
        with self.assertRaises(NotFound):
            self.app.emergency.request_access(self.home, self.nurse, self.source, "pat_unknown",
                                              self.reason(), ["profile"], 30, "emg-missing")
        request = self.request(key="emg-visibility")
        self.assertEqual(self.app.emergency.request_detail(self.home, self.nurse, request["id"])["id"], request["id"])
        with self.assertRaises(Forbidden):
            self.app.emergency.request_detail(self.home, self.clinician_b, request["id"])
        with self.assertRaises(Forbidden):
            self.app.emergency.list_requests(self.home, self.nurse)
        self.assertEqual(len(self.app.emergency.list_requests(self.home, self.auditor)), 1)


    def test_http_emergency_access_end_to_end(self):
        import json as _json

        def call(client, method, path, token, body=None, key=None):
            headers = {"X-Clinic-ID": self.home, "Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            if key:
                headers["Idempotency-Key"] = key
            request = Request(base + path, data=_json.dumps(body).encode() if body is not None else None,
                              method=method, headers=headers)
            try:
                with urlopen(request, timeout=3) as response:
                    return response.status, _json.loads(response.read())
            except HTTPError as error:
                return error.code, _json.loads(error.read())

        def login(staff_id, password):
            request = Request(base + "/auth/token",
                              data=_json.dumps({"staff_id": staff_id, "password": password}).encode(),
                              method="POST", headers={"X-Clinic-ID": self.home, "Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                return _json.loads(response.read())["access_token"]

        self.app.set_password(self.home, self.nurse, self.nurse, "NursePassphrase!2026")
        self.app.set_password(self.home, self.clinician, self.clinician, "DoctorPassphrase!2026")
        self.app.set_password(self.home, self.auditor, self.auditor, "AuditorPassphrase!2026")
        server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            nurse_token = login(self.nurse, "NursePassphrase!2026")
            doctor_token = login(self.clinician, "DoctorPassphrase!2026")
            auditor_token = login(self.auditor, "AuditorPassphrase!2026")
            status, request = call(nurse_token, "POST", "/emergency-access/requests", nurse_token,
                                   {"source_clinic_id": self.source, "patient_id": self.source_patient["id"],
                                    "clinical_reason": self.reason(), "sections": ["profile", "incidents"],
                                    "ttl_minutes": 30}, key="http-emg-1")
            self.assertEqual(status, 201)
            self.assertEqual(request["state"], "requested")
            # 申请人本人通过 HTTP 自批被拒。
            status, _ = call(nurse_token, "POST", f"/emergency-access/requests/{request['id']}/decide",
                             nurse_token, {"decision": "approve", "expected_version": 1})
            self.assertEqual(status, 403)
            status, granted = call(doctor_token, "POST", f"/emergency-access/requests/{request['id']}/decide",
                                   doctor_token, {"decision": "approve", "expected_version": 1,
                                                  "granted_sections": ["profile"], "granted_ttl_minutes": 15})
            self.assertEqual(status, 200)
            self.assertEqual(granted["granted_sections"], ["profile"])
            status, read = call(nurse_token, "POST", f"/emergency-access/requests/{request['id']}/read",
                                nurse_token, {"section": "profile"})
            self.assertEqual(status, 200)
            self.assertEqual(read["data"]["display_name"], "急诊患者")
            status, _ = call(nurse_token, "POST", f"/emergency-access/requests/{request['id']}/read",
                             nurse_token, {"section": "incidents"})
            self.assertEqual(status, 403)
            status, review = call(auditor_token, "POST", f"/emergency-access/requests/{request['id']}/review",
                                  auditor_token, {"conclusion": "appropriate", "note": "夜间急诊依据充分"})
            self.assertEqual(status, 200)
            self.assertEqual(review["reviewer_id"], self.auditor)
            status, detail = call(auditor_token, "GET", f"/emergency-access/requests/{request['id']}", auditor_token)
            self.assertEqual(status, 200)
            self.assertEqual([item["section"] for item in detail["reads"]], ["profile"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
