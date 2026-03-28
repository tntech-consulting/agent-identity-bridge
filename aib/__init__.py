"""Agent Identity Bridge — Portable identity for AI agents across protocols."""
__version__ = "2.15.1"

from .passport import PassportService
from .translator import CredentialTranslator
from .policy_engine import PolicyEngine
from .integrations import AIBToolkit, get_langchain_tools, get_crewai_tools, get_openai_agents_tools
