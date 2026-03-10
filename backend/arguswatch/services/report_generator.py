"""
report_generator.py - passthrough wrapper for pdf_report.py.
Keeps agent/tools.py import working cleanly.
"""
from arguswatch.services.pdf_report import generate_pdf_report as _impl


async def generate_pdf_report(customer_id: int, period_days: int = 30) -> dict:
    """Passthrough to pdf_report.generate_pdf_report."""
    return await _impl(customer_id, period_days)


__all__ = ["generate_pdf_report"]
