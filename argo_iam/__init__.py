"""Argo IAM Governance Layer.

A Python prototype of an identity and access governance layer that sits in
front of Argo CD. It adds MFA, session management, role-aware authorization,
just-in-time (JIT) privilege elevation with approval, and a tamper-evident
audit trail, and reaches Argo CD only through an adapter.
"""

__version__ = "0.1.0"
