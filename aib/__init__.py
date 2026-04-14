"""Agent Identity Bridge — Cryptographic identity for AI agents."""
__version__ = "2.16.0"

from .passport import PassportService
from .translator import (
    CredentialTranslator,
    public_key_to_did_key,
    did_key_to_public_key_hex,
    did_key_to_did_document,
)
from .policy_engine import (
    PolicyEngine,
    PolicyRule,
    PolicyContext,
    PolicyDecision,
    RuleType,
    DeliverableContract,
    Criterion,
    CriterionStatus,
    ContractManager,
)
from .integrations import AIBToolkit, get_langchain_tools, get_crewai_tools, get_openai_agents_tools
from .cloud import AIBCloud, AIBCloudError
