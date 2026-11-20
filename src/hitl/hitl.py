"""
Lab 11 — Optional enrichment: Human-in-the-Loop Design
  (Không chấm — tham khảo. Tóm tắt nộp do scripts/grade.py tự sinh,
   không viết report/*.md tay.)
  - Confidence Router
  - 3 HITL decision points
"""
from dataclasses import dataclass
import math


# ============================================================
# Optional enrichment: ConfidenceRouter (không chấm)
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Confidence must be finite and between 0 and 1")
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", confidence, f"High-risk action: {action_type}", "high", True)
        if not response.strip():
            return RoutingDecision("escalate", confidence, "Empty response needs review", "high", True)
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", confidence, "High confidence", "low", False)
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", confidence, "Medium confidence needs review", "normal", True)
        return RoutingDecision("escalate", confidence, "Low confidence", "high", True)


# ============================================================
# Optional enrichment: 3 HITL decision points (không chấm)
# Không bắt buộc điền. Tóm tắt bài nộp: chạy scripts/grade.py
# (tự sinh lab_report.md) — không viết report tay.
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Phê duyệt chuyển tiền",
        "trigger": "Mọi đề xuất transfer_money, bất kể độ tin cậy.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Người yêu cầu đã xác thực, số tiền, người nhận, hạn mức và dấu hiệu gian lận; che PII không cần thiết.",
        "example": "Chat đề xuất chuyển 50 triệu đồng sau khi đọc một email ngoài.",
        "approval_path": "Chờ duyệt gắn đúng nội dung giao dịch; từ chối hoặc hết hạn thì không thực hiện. Thay đổi người nhận/số tiền phải duyệt lại.",
        "audit_fields": "request_id, authenticated_user, action, redacted_payload, payload_hash, reviewer_id, decision, decided_at, expires_at",
    },
    {
        "id": 2,
        "name": "Đối chiếu câu trả lời chưa chắc chắn",
        "trigger": "Độ tin cậy từ 0.7 đến dưới 0.9 hoặc dữ liệu lãi suất mâu thuẫn.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Câu hỏi, câu trả lời dự thảo, nguồn chính sách có ngày hiệu lực và điểm mâu thuẫn.",
        "example": "Hai tài liệu ghi lãi suất tiết kiệm 12 tháng khác nhau.",
        "approval_path": "Chuyên viên kiểm nguồn rồi duyệt/sửa; từ chối hoặc quá thời gian thì chuyển hỗ trợ, không tự gửi số liệu.",
        "audit_fields": "request_id, source_ids, source_versions, draft_hash, proposed_diff, reviewer_id, decision, reason, decided_at",
    },
    {
        "id": 3,
        "name": "Giám sát bất thường và rò rỉ",
        "trigger": "Block rate hoặc số lần rate limit vượt ngưỡng; phát hiện PII/secret.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Metrics theo cửa sổ, lớp chặn, nhật ký đã che dữ liệu và phiên bản chính sách.",
        "example": "Một phiên liên tục gửi yêu cầu lấy cấu hình nội bộ.",
        "approval_path": "Hệ thống chặn ngay theo policy; người vận hành xác nhận sự cố và chọn cách xử lý. Hết thời gian vẫn giữ chặn, không tự mở quyền.",
        "audit_fields": "alert_id, request_ids, metric, threshold, policy_version, reviewer_id, decision, remediation, decided_at",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
