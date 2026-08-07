# Day 11 — Controlled Agent Security (2026)

- Họ tên: **Vũ Bảo Chinh**
- MSSV: **2A202601448**
- Framework: Google ADK + deterministic Python guardrails; NeMo là lớp tùy chọn.

## Chạy bài

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONIOENCODING='utf-8'
$env:STUDENT_ID='2A202601448'
cd src
python main.py --part 2
python main.py --part 3
python main.py --part 4
python main.py --part 5
python main.py --part 1
cd ..
pytest tests/smoke tests/public -q
python scripts/grade.py --submission-dir . --out outputs/grade_report.json
```

## Thiết kế

Pipeline: rate limit → Unicode/provenance input guardrails → model → output redaction + judge → HITL/action gateway → exact egress allowlist → audit/monitoring. Artifact nộp nằm trong `outputs/`; báo cáo tại `report/2A202601448_report.md`.

Không commit `.env` hoặc API key. Nguồn tham khảo: Google ADK, NeMo Guardrails, OWASP Top 10 for LLM.
