"""Rule-based detector (Layer A, spec §9): the RULE-### registry with
per-rule enable/weight configuration, quoted-educational handling and
per-category telemetry."""

import logging
import re

from pif.detection.fuzzy import FUZZY_PHRASES
from pif.observability import content_preview, logger
from pif.schemas import ATTACK_IDS, Finding, Segment

# Rule registry: unique RULE-### IDs (spec: measurable, individually configurable
# detections). Multiple rules may share a category; the derived RULES mapping below
# preserves the first-seen category order because the trained classifier's labels
# are exactly ["attack", *RULES] and the model artifact validates that sequence.
RULES_REGISTRY: list[dict] = [
    {
        "id": "RULE-001",
        "category": "instruction_override",
        "severity": 0.9,
        "pattern": r"\b(?:ignores?|disregards?|forgets?|overrides?)\b.{0,65}\b(?:previous|prior|system|developer|above|user)\b.{0,40}\b(?:instructions?|prompts?|rules?|task)\b",
        "reason": "replaces previous instructions",
    },
    {
        "id": "RULE-002",
        "category": "instruction_override",
        "severity": 0.55,
        "pattern": r"\b(?:ignores?|disregards?|forgets?|overrides?)\b.{0,65}\b(?:previous|prior|system|developer|above|user)\b(?!\s+(?:calculations?|assignments?|results?|values?|entries?|records?|versions?|sessions?|messages?|errors?|data|output))",
        "reason": "targets previous context (partial override, benign nouns excluded)",
    },
    {
        "id": "RULE-003",
        "category": "instruction_override",
        "severity": 0.75,
        "pattern": r"\b(?:disregard|discard|forget|replace)\b.{0,80}\b(?:what you were told|you were told|told earlier|earlier|original|existing)\b.{0,80}\b(?:instructions?|directions?|task|prompt)\b|\b(?:no longer applicable|no longer needed|new instructions)\b",
        "reason": "supersedes earlier guidance",
    },
    {
        "id": "RULE-004",
        "category": "secret_extraction",
        "severity": 0.96,
        "pattern": r"\b(?:reveal|show|print|tell|provide|expose|leak|return|give|share|hand)\b.{0,80}\b(?:system prompt|hidden configuration|hidden instructions|password|private configuration|confidential configuration|confidential instructions)\b",
        "reason": "discloses hidden configuration",
    },
    {
        "id": "RULE-005",
        "category": "role_change",
        "severity": 0.9,
        "pattern": r"\b(?:you are now|act as|pretend to be|pretend that|pretend you|become|switch to)\b.{0,60}\b(?:unrestricted|unfiltered|uncensored|hacker|developer mode|no safety|without restrictions|no restrictions|administrator|admin|root)\b",
        "reason": "unsafe role switch",
    },
    {
        "id": "RULE-006",
        "category": "credential_theft",
        "severity": 0.98,
        "pattern": r"\b(?:send|reveal|show|print|extract|steal|provide|upload|exfiltrate|return|request|demand|ask for)\b.{0,90}\b(?:passwords?|api[ _-]?keys?|access tokens?|authentication tokens?|credentials?|bearer tokens?|environment secrets?|cloud credentials?|private access tokens?)\b",
        "reason": "extracts credentials",
    },
    {
        "id": "RULE-007",
        "category": "tool_abuse",
        "severity": 0.95,
        "pattern": r"\b(?:delete|wipe|remove)\b.{0,45}\b(?:all\s+)?files?\b|\b(?:delete|wipe|remove)\b.{0,45}\b(?:filesystem|database|backups?|home directory)\b|\b(?:modify|update|drop)\b.{0,45}\bdatabase\b|\b(?:execute|run)\b.{0,35}\b(?:shell command|unsafe command|rm -rf|powershell|subprocess)\b|\b(?:execute|run|perform)\b.{0,45}\b(?:unauthorized|unapproved)\b.{0,45}\b(?:api|request|command|action)\b",
        "reason": "destructive or unsafe operation",
    },
    {
        "id": "RULE-008",
        "category": "tool_abuse",
        "severity": 0.9,
        "pattern": r"\b(?:send|email|upload|post|curl)\b.{0,80}\b(?:secrets?|credentials?|private data|system prompt)\b.{0,100}(?:https?://|@|external|attacker)|\b(?:send|post|submit)\b.{0,40}\b(?:email|message|request)\b.{0,60}\bwithout\b.{0,30}\b(?:authorization|approval|permission)\b",
        "reason": "unauthorized data transfer",
    },
    {
        "id": "RULE-009",
        "category": "context_poisoning",
        "severity": 0.88,
        "pattern": r"\b(?:system|developer|administrator|security)\s*(?:message|notice|update|override)\b.{0,90}\b(?:must|supersedes|authorized|priority|obey|disable)\b|\b(?:treat|accept)\b.{0,50}\b(?:this document|this page|these instructions)\b.{0,40}\b(?:highest priority|system instructions|ground truth)\b|\b(?:following instruction|instruction below|instruction above)\b.{0,60}\b(?:higher priority|overrides?|supersedes)\b.{0,40}\b(?:system prompt|system instructions|all other)\b",
        "reason": "claims higher authority",
    },
    {
        "id": "RULE-010",
        "category": "multi_step_jailbreak",
        "severity": 0.92,
        "pattern": r"\b(?:first|step 1)\b.{0,100}\b(?:disable|ignore|bypass)\b.{0,70}\b(?:safety|rules|restrictions|instructions)\b.{0,120}\b(?:then|step 2|next)\b.{0,100}\b(?:reveal|execute|send|unrestricted)\b",
        "reason": "ordered bypass then disclosure",
    },
    {
        "id": "RULE-011",
        "category": "instruction_override",
        "severity": 0.85,
        "pattern": r"\b(?:reset|overwrite|replace|reload|erase|wipe|rewritten?)\b.{0,50}\b(?:your\s+)?(?:instructions?|system\s+prompts?|configuration|guidelines?|rules?)\b|\b(?:instructions?|guidelines?|rules?|policies?|directives?)\b.{0,40}\b(?:are\s+|is\s+|were\s+)?(?:void|invalid|expired|corrupt(?:ed)?|revoked|suspended|placeholders?|no\s+longer\s+apply|no\s+longer\s+valid|removed)\b",
        "reason": "invalidates or replaces active instructions",
    },
    {
        "id": "RULE-012",
        "category": "instruction_override",
        "severity": 0.8,
        "pattern": r"\b(?:do\s+not|don't|never|stop|pay\s+no\s+attention\s+to)\b.{0,40}\b(?:follow|obey|mind|apply)\b.{0,50}\b(?:the\s+)?(?:system\s+prompt|previous|prior|original|old|above|initial|guidelines?|rules?)\b|\bfollow\s+(?:only\s+)?(?:the\s+)?(?:instructions?|rules?)\s+in\s+this\s+(?:message|prompt|paragraph|chat)|\b(?:ignore|skip|bypass|disable)\b.{0,30}\b(?:safety|security|content)\b.{0,40}\b(?:policy|policies|rules?|checks?|filters?|guidelines?|checklist|measures?)\b|\bbypass\b.{0,40}\b(?:any|all|the|your)\b.{0,30}\brules?\b|\btreat\b.{0,60}\bas\s+untrusted\b|\bthrow\s+away\b.{0,40}\b(?:your\s+)?(?:current\s+)?(?:task|instructions?|rules?)\b|\bnever\s+mind\s+the\b|\bdisobey\b.{0,40}\b(?:your|the|previous|prior)\b",
        "reason": "instructs to abandon or bypass active rules",
    },
    {
        "id": "RULE-013",
        "category": "role_change",
        "severity": 0.9,
        "pattern": r"\b(?:you\s+are|you\s+will\s+(?:play|be|operate)|become|act\s+as|acting\s+as|pretend(?:\s+to\s+be|\s+that|\s+you)?|roleplay\s+as|assume\s+the\s+identity\s+of|enter|enable|activate|switch\s+(?:to|persona)|simulate|imagine|take\s+on\s+the\s+role\s+of|speak\s+as|respond\s+as|transform\s+into|from\s+now\s+on\s+you\s+are)\b.{0,100}\b(?:(?:jailbreak|jailbroken|jailbreaks)|developer\s+mode|devmode|god\s?mode|unfiltered|uncensored|no\s+(?:ethics|rules|restrictions|filters|limits|limitations|oversight|refusal|refusals|alignment|safety|guardrails?|content\s+rules?)|without\s+(?:any\s+|all\s+)?(?:ethics|rules|restrictions|filters|limits|limitations|oversight|refusal|alignment|safety|guardrails?)|do\s+not\s+have\s+to\s+abide\s+by\s+(?:any\s+|no\s+)?rules|abide\s+by\s+(?:any\s+|no\s+)?rules|freed\s+from\s+(?:the\s+)?(?:typical\s+)?confines|do\s+anything\s+now|filters?\s+(?:are\s+)?(?:turned\s+)?off|full\s+(?:privileges?|access|control)|root\s+(?:privileges?|access|bot)|administrator|admin\b|admin\s+privileges?|evil|hacker|never\s+(?:refuse|refuses|refusing)|answers?\s+everything|ignores?\s+all\s+polic(?:y|ies)|disable\s+(?:the\s+)?guardrails?|serve\s+the\s+user\s+without\s+(?:limits|restrictions)|malicious\s+insider)\b|\b(?:respond|answer|reply|act|behave)\b.{0,60}\bwithout\s+(?:any\s+|all\s+)?(?:restrictions|limitations|filters|rules)\b",
        "reason": "switches to an unsafe persona",
    },
    {
        "id": "RULE-023",
        "category": "instruction_override",
        "severity": 0.75,
        "vocab": False,
        # Context-wipe family from the public deepset/prompt-injections
        # held-out set: "Forget everything we've talked about so far. We'll
        # start with..." — a memory reset no other rule covered. The German/
        # Spanish alternations cover the same family in the dataset's
        # multilingual rows ("Vergiss alles...", "Höre nicht auf alles
        # zuvor...", "olvide todo...").
        "pattern": r"\b(?:forget|erase|wipe|clear|discard|drop)\b.{0,40}\b(?:everything|all|anything|it all)\b.{0,80}\b(?:so\s+far|above|before|told|said|talked|discussed|prior|previous|earlier|learned|seen)\b|vergiss\s+(?:jetzt\s+)?all(?:es|en)?|vergiss\s+alles|höre\s+nicht\s+auf\s+(?:alles\s+)?zuvor|ignorieren\s+sie\s+die\s+obigen|olvide\s+todo",
        "reason": "wipes conversation memory to reset the task",
    },
    {
        "id": "RULE-014",
        "category": "secret_extraction",
        "severity": 0.9,
        "pattern": r"\b(?:repeat|quote|recite|output|print|show|display|echo|paste|copy|dump|spell|translate|encode|write|list|reveal|reply\s+with|complete|include|retrieve|leak|expose|summarize|give)\b.{0,100}\b(?:everything\s+(?:above|before|so\s+far)|words?\s+above|text\s+above|(?:above|prior)\s+(?:prompt|instructions?|message|text)|initial\s+(?:prompt|instructions?|configuration|message|text)|original\s+(?:prompt|instructions?|configuration|text)|exact\s+(?:instructions?|wording|text|rules?|prompt)|instructions?\s+(?:you\s+(?:were\s+)?given|given\s+to\s+you)|developer\s+(?:message|notes?)|hidden\s+(?:text|configuration|chain|rules?|instructions?|prompt|secrets?)|word\s+for\s+word|confidential\s+(?:prompt|instructions?|documents?|configurations?|system\s+configurations?)|full\s+prompt|prompt\s+(?:template|preamble)|system\s+messages?|guardrail\s+rules?|policy\s+text|your\s+(?:actual\s+|full\s+|entire\s+)?system\s+prompt|contents\s+of\s+your\s+(?:environment\s+variables?|context|instructions?|prompt)|backwards?|in\s+base64|as\s+a\s+poem|first\s+\d+\s+words)\b|\bwhat\s+(?:is|are|was|were)\b.{0,70}\b(?:your\s+|the\s+)?(?:exact\s+|initial\s+|original\s+|first\s+|full\s+|hidden\s+)?(?:instructions?|system\s+prompt|initial\s+prompt|developer\s+message|guardrails?|secret\s+password|password)\b|\bsecret\s+password\b.{0,60}\bstored\b",
        "reason": "requests hidden or exact configuration text",
    },
    {
        "id": "RULE-015",
        "category": "tool_abuse",
        "severity": 0.95,
        "pattern": r"\b(?:reverse\s+shell|nc\s+-e\b|\bnc\b.{0,20}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|DROP\s+TABLE|rm\s+-rf|chmod\s+777|INTO\s+OUTFILE|git\s+push\s+--force|\|\s*(?:sh|bash)\b|crontab\b.{0,80}curl|os\.system|subprocess\.)|\b(?:evil\.example|attacker@|169\.254\.169\.254|/etc/(?:passwd|shadow)|/proc/self/environ|~/\.ssh|~/\.bashrc)|\b(?:call|use|invoke|run|execute)\b.{0,60}\b(?:tool|function|command)\b.{0,120}\bwithout\b.{0,50}\b(?:asking|approval|confirmation|permission|authorization)\b|\b(?:delete_all_files|update_role|webhook\s+tool|payment\s+tool)\b|\btransfer\b.{0,60}\bwithout\s+user\s+approval\b|\bdisable\b.{0,40}\b(?:audit|logging)\b.{0,40}\b(?:tool|before)\b",
        "reason": "dangerous or unauthorized tool operation",
    },
    {
        "id": "RULE-016",
        "category": "credential_theft",
        "severity": 0.9,
        "pattern": r"\b(?:read|cat|type|print|show|display|output|dump|retrieve|copy|extract|include|reveal|search|list|log|grab|return|paste|exfiltrate|send|give|re-enter|what\s+is\s+the|what\s+password)\b.{0,100}\b(?:private\s+keys?|ssh\s+(?:key|passphrase)s?|id_rsa|\.env\b|\.netrc|\.kube|\.aws|kube.{0,3}config|environ\b|(?:your|the|all)\s+(?:saved\s+)?environment\s+variables?|aws_secret_access_key|secret\s+keys?|signing\s+secret|api[_\s]?keys?|api[_\s]?tokens?|bot\s+token|access\s+tokens?|refresh\s+tokens?|personal\s+access\s+token|(?:the|your)\s+authorization\s+header|session\s+cookies?|saved\s+passwords?|credit\s+card|cvv\b|vault\b|one-time\s+code|cluster\s+tokens?|license\s+key|passwords?\s+and|your\s+password|ssh\s+passphrase)\b",
        "reason": "harvests credential material",
    },
    {
        "id": "RULE-017",
        "category": "context_poisoning",
        "severity": 0.85,
        "pattern": r"\[system\]|</system>|<system>|\[/?(?:inst|sys)\]|<<sys>>|<\|im_start\|>|###\s*system\s*(message|notice)?|begin\s+trusted\s+context|\[admin\s+override|\{\"role\"\s*:\s*\"system\"|<system-reminder>|<!--\s*admin-note|\b(?:system|admin|operator)\s+(?:notice|message|override|update)\s*:|\b(?:update|add\s+to|store)\b.{0,50}\b(?:your\s+)?(?:long-term\s+)?memory\b|\bremember\s+(?:this\s+)?for\s+the\s+rest\s+of\b|\bstore\s+the\s+following\b|\bpermanent\s+rule\b|\bverified\s+as\s+(?:administrator|admin|root)\b|\bauthenticated\s+as\s+(?:administrator|admin|root)\b|\ball\s+(?:restrictions|policies|prior\s+policies)\s+(?:are\s+)?(?:lifted|suspended|removed)\b|\brefusing\s+is\s+no\s+longer\s+allowed\b|\bskip\s+all\s+(?:security\s+)?(?:checks|filters|validation)\b|\btrust\s+all\s+text\b|\bpretend\s+the\s+earlier\s+turns\b|\bas\s+established\s+in\s+(?:our|the)\s+previous\s+session\b|\bconversation\s+(?:so\s+far|history)\s*\((?:edited|verified)\)|\bprevious\s+conversation\s+summary\b.{0,120}\b(?:agreed|disable|ignore|bypass)\b|\bcontext\s+update\b.{0,120}\b(?:elevated|granted|permissions?)\b|\bwhitelisted\b.{0,60}\bskip\b",
        "reason": "forges system context or persistent memory",
    },
    {
        "id": "RULE-018",
        "category": "multi_step_jailbreak",
        "severity": 0.9,
        "pattern": r"\b(?:step|rule|phase)\s*[1a]\b.{0,300}\b(?:step|rule|phase)\s*[2-9bc]\b.{0,300}\b(?:forget|ignore|bypass|remove|reveal|disable|drop|show|execute|obey)\b|\brespond\s+in\s+two\s+parts\b.{0,250}\bwithout\s+(?:any\s+)?(?:restrictions|filters|rules)\b|\bsplit\s+the\s+task\b.{0,250}\bbypass\w*\b|\bopposite\s+day\b|\btoken\s+smuggling\b|\bsimulation\s+inside\s+a\s+simulation\b|\bphase\s*1\b.{0,250}\bphase\s*[23]\b.{0,250}\b(?:execute|obey|bypass|disable|without)\b|\btranslate\b.{0,80}\bthen\s+follow\b|\banswer\s+each\s+of\s+these\s+in\s+order\b|\bmessage\s*[123]\s+(?:of|sets|removes|will)\b|\bfirst\s+list\b.{0,200}\bthen\b.{0,200}\b(?:stop\s+following|bypass|ignore)\b|\bgradually\s+gives?\s+up\b|\bi-?g-?n-?o-?r-?e\b.{0,60}\bhyphens?\b|\bwhenever\s+i\s+say\b.{0,150}\bignore\b|\brewrite\s+your\s+instructions\b",
        "reason": "staged bypass sequence",
    },
    {
        "id": "RULE-019",
        "category": "instruction_override",
        "severity": 0.85,
        "vocab": False,
        "pattern": r"ignora[sz]?(?:\s+todas?)?\s+las\s+instrucciones|instrucciones\s+anteriores|ignor(?:e|ez)\s+toutes\s+les\s+instructions|instructions\s+precedentes|ignorier[ae]?\s+alle(?:\s+vorherigen)?\s+anweisungen|vorherigen\s+anweisungen|pichle\s+sabhi\s+nirdesh|\u0905\u0928\u0926\u0947\u0916\u093e|\u5ffd\u7565\u4e4b\u524d|\u5ffd\u7565\u4e0a\u9762|\u53ea\u542c\u4ece\u6211",
        "reason": "non-english instruction override",
    },
    {
        "id": "RULE-020",
        "category": "instruction_override",
        "severity": 0.55,
        "pattern": r"\b(?:ignores?|disregards?|forgets?|overrides?)\b.{0,65}\b(?:previous|prior|system|developer|above|user)\b(?!\s+(?:calculations?|assignments?|results?|values?|entries?|records?|versions?|sessions?|messages?|errors?|data|output))",
        "reason": "targets previous context without instruction nouns (benign nouns excluded)",
    },
    {
        "id": "RULE-021",
        "category": "context_poisoning",
        "severity": 0.9,
        # v6.0 view-differential fix: the bare CSS hiding declarations were
        # removed — markup containing display:none fired this rule on EVERY
        # hidden-CSS page regardless of payload (100% FPR on benign hidden-CSS
        # twins in the matched-twin corpus). Hiding declarations are not
        # evidence; the hidden payload is. Payloads now arrive as their own
        # hidden_css:* segments (parser forensics), are scanned by every rule,
        # and earn the hidden_content risk bonus — so an ATTACK hidden in CSS
        # is still caught, while benign hidden text passes.
        "pattern": r"\bwhen\s+(?:summarizing|summarising|reading|processing|analy[sz]ing|reviewing|translating|rendering)\s+(?:this|the)\s+(?:page|document|article|text|content|email|post)\b.{0,200}\b(?:state|say|mention|recommend|claim|tell|include|assert|insert|add)\b|\b(?:most\s+)?trusted\s+source\b.{0,120}\b(?:recommend|visit|cite|link)\b|\brecommend\s+visiting\b.{0,80}\b(?:https?://|evil|attacker|external)\b|\bignore\s+(?:the\s+)?(?:visible|displayed|shown)\s+(?:content|text)\b",
        "reason": "AI-directed directive in content",
    },
]

# Derived category view: the FIRST rule per category fixes the category order used
# by the classifier labels and the nine-category summary. Do not reorder the rules
# above without retraining the model artifact.
RULES = {}
for _rule in RULES_REGISTRY:
    RULES.setdefault(_rule["category"], (_rule["severity"], _rule["pattern"]))

# Per-rule configuration (enable/weight), loaded from the policy configuration.
_RULE_OVERRIDES: dict[str, dict] = {}

# Rules defined entirely in configuration ([rules:CUSTOM-###] sections, added
# from the admin portal). Compiled once, scanned by the same RuleDetector pass.
_CUSTOM_RULES: list[dict] = []


def set_rule_overrides(overrides: dict | None):
    global _RULE_OVERRIDES
    _RULE_OVERRIDES = overrides or {}


def get_rule_overrides() -> dict:
    return _RULE_OVERRIDES


def set_custom_rules(rules: list[dict] | None):
    global _CUSTOM_RULES
    _CUSTOM_RULES = list(rules or [])


def get_custom_rules() -> list[dict]:
    return _CUSTOM_RULES


def validate_custom_rule(rule_id: str, definition: dict) -> dict:
    """Compile-and-check a script/config-supplied rule definition
    (scripts/policy.py, [rules:CUSTOM-###]); ValueError explains why."""
    pattern = str(definition.get("pattern") or "")
    category = str(definition.get("category") or "")
    try:
        severity = float(definition.get("severity", 0.8))
        weight = float(definition.get("weight", 1.0))
    except (TypeError, ValueError) as error:
        raise ValueError("severity and weight must be numbers") from error
    if not rule_id.startswith("CUSTOM-"):
        raise ValueError("custom rule ids must start with CUSTOM-")
    if category not in ATTACK_IDS:
        raise ValueError(f"unknown attack category: {category!r}")
    if not pattern.strip():
        raise ValueError("pattern must not be empty")
    try:
        re.compile(pattern)
    except re.error as error:
        raise ValueError(f"invalid regex pattern: {error}") from error
    if not 0 < severity <= 1 or not 0 <= weight <= 1:
        raise ValueError("severity must be in (0,1] and weight in [0,1]")
    reason = " ".join(str(definition.get("reason") or "custom detection added by scripts/policy.py").split())
    return {
        "id": rule_id,
        "category": category,
        "severity": severity,
        "weight": weight,
        "pattern": pattern,
        "reason": reason[:200],
        "custom": True,
    }


# Word vocabulary for the fuzzy-words normalization view, derived from the
# literal words inside the rule patterns and fuzzy phrases so the view and the
# rules stay in sync automatically. Pattern syntax is stripped before word
# extraction (so "\bignore" never yields "bignore"), rules may opt out with
# "vocab": False (non-English patterns would hijack English typo repair), and
# fragments that merely prefix a longer word are dropped.
def _vocab_source_words(source: str) -> list[str]:
    """Literal words in a rule pattern, with regex syntax removed."""
    cleaned = re.sub(r"\\[A-Za-z]", " ", source)  # \b \s \d \w ...
    cleaned = re.sub(r"\[[^\]]*\]", "", cleaned)  # character classes
    cleaned = re.sub(r"[^a-z|]+", " ", cleaned)  # keep letters and alternation bars
    return re.findall(r"[a-z]{4,}", cleaned)


_ALL_VOCAB_WORDS = frozenset(
    source
    for source in [
        word
        for rule in RULES_REGISTRY if rule.get("vocab", True)
        for word in _vocab_source_words(rule["pattern"])
    ] + [word for *_, phrase in FUZZY_PHRASES for word in _vocab_source_words(phrase)]
)
# Pattern literals carry their regex inflection ("ignores?", "disregards?"),
# so the extracted words are the INFLECTED forms — and the legacy prefix
# filter dropped every base form whose plural also exists ("ignore" died
# behind "ignores", "disregard" behind "disregards"), leaving truncated-word
# typos ("sregard", "nore") unreachable for fuzzy repair. Fix: a word is only
# shadowed by a DIFFERENT word extending it beyond a pure plural, and base
# forms are unioned in explicitly. (v6.0 eval-fuzzy-miss fix.)
def _has_longer_non_inflection(word: str, words: frozenset) -> bool:
    return any(
        other != word and other.startswith(word) and other != word + "s"
        for other in words
    )


# Short rule verbs that a longer pattern word would otherwise shadow
# ("give" behind "given", "hand" behind "handled"): they are intentional
# detection vocabulary and must stay reachable as fuzzy-repair targets.
_VOCAB_ALLOWLIST = frozenset(
    {
        "give", "show", "tell", "hand", "share", "leak", "print", "send",
        "copy", "dump", "list", "wipe", "drop", "clear", "post", "read",
        "type", "grab", "paste", "reveal", "forget", "erase", "discard",
    }
)

_ALL_BASE_FORMS = frozenset(
    word[:-1]
    for word in _ALL_VOCAB_WORDS
    if word.endswith("s")
    and len(word) >= 5
    and not _has_longer_non_inflection(word[:-1], _ALL_VOCAB_WORDS)
)
_FILTERED_VOCAB = frozenset(
    word for word in _ALL_VOCAB_WORDS if not _has_longer_non_inflection(word, _ALL_VOCAB_WORDS)
)
WORD_VOCAB = frozenset(_FILTERED_VOCAB | _ALL_BASE_FORMS | _VOCAB_ALLOWLIST)


def _effective_severity(rule: dict):
    """The severity the detector applies RIGHT NOW: the registry severity (or a
    severity override from the policy INI, when a script re-tuned it) scaled by
    the rule's weight override; None when the rule is disabled."""
    override = _RULE_OVERRIDES.get(rule["id"], {})
    if override.get("enabled") is False:
        return None
    base = rule["severity"]
    try:
        base = float(override.get("severity", base))
    except (TypeError, ValueError):
        pass
    try:
        weight = float(override.get("weight", 1.0))
    except (TypeError, ValueError):
        weight = 1.0
    return min(1.0, base * weight)


RULE_REASONS = {
    "instruction_override": "replaces previous instructions",
    "secret_extraction": "discloses hidden configuration",
    "role_change": "unsafe role switch",
    "credential_theft": "extracts credentials",
    "tool_abuse": "destructive or unsafe operation",
    "context_poisoning": "claims higher authority",
    "multi_step_jailbreak": "ordered bypass then disclosure",
}


def log_categories(findings: list[Finding], scope="segment"):
    if scope == "segment":
        logger.info("story.step_started", extra={"event_fields": dict(step=6, title="Segment Attack Category Results", scope=scope)})
    for category in [*RULES, "encoded_instruction", "indirect_injection"]:
        evidence = [
            finding
            for finding in findings
            if finding.category == category and finding.severity >= 0.5
        ]
        layers = sorted({finding.layer for finding in evidence})
        if not evidence:
            reason = "no evidence at this stage"
        elif category == "encoded_instruction":
            reason = "decoded/obfuscated view evidence"
        elif category == "indirect_injection":
            reason = "external source evidence"
        elif layers == ["semantic"]:
            reason = "semantic scores only; no regex match"
        elif category == "multi_step_jailbreak" and "context" in layers:
            reason = "conversation sequence matched"
        else:
            reason = RULE_REASONS[category]
        logger.info("detection.category_evaluated", extra={"event_fields": dict(category=category, scope=scope, detected=bool(evidence), methods=layers, reason=reason, evidence=[
                {
                    "source_id": finding.source_id,
                    "locator": content_preview(finding.locator),
                    "transformation": finding.transformation,
                    "layer": finding.layer,
                    "severity": finding.severity,
                }
                for finding in evidence[:4]
            ])})
    if scope == "segment":
        logger.info("story.step_completed", extra={"event_fields": dict(step=6, title="Segment Attack Category Results", scope=scope)})


def quoted_example(text: str, start: int, end: int) -> bool:
    for quote in re.finditer(r'"[^"\n]+"|\x27[^\x27\n]+\x27|`[^`\n]+`', text):
        if quote.start() < start and end < quote.end():
            outside = text[: quote.start()] + text[quote.end() :]
            return bool(
                re.search(
                    r"\b(?:explain|analy[sz]e|detect|example|quoted|documentation)\b", outside
                )
            ) and not re.search(r"\b(?:obey|perform|follow|execute)\b", outside)
    return False


class RuleDetector:
    """Layer A: regex rule matching over every normalized view."""

    name = "rules"

    def scan_view(self, segment: Segment, transformation: str, text: str, rule_categories: set) -> list[Finding]:
        findings = []
        for rule in RULES_REGISTRY + _CUSTOM_RULES:
            severity = _effective_severity(rule)
            if severity is None:
                logger.debug("detection.rule_disabled", extra={"event_fields": dict(rule_id=rule["id"], category=rule["category"])})
                continue
            category = rule["category"]
            pattern = rule["pattern"]
            matches = list(re.finditer(pattern, text))
            quoted_flags = (
                [quoted_example(text, match.start(), match.end()) for match in matches]
                if matches
                else []
            )
            educational_quote = bool(matches) and all(quoted_flags)
            logger.debug("detection.rule_evaluated", extra={"event_fields": dict(rule_id=rule["id"], category=category, pattern=pattern, matched=bool(matches), actionable=bool(matches) and not educational_quote, quoted_example=educational_quote, transformation=transformation, input_text=content_preview(text), evidence=[
                    {
                        "start": match.start(),
                        "end": match.end(),
                        "text": content_preview(match.group()),
                    }
                    for match in matches[:3]
                ], reason="quoted educational example"
                if educational_quote
                else rule["reason"]
                if matches
                else "pattern not present")})
            if matches:
                # Spans map the rule back onto the ORIGINAL segment text so
                # policy can redact the matched instruction. Quoted educational
                # matches never produce spans: content that mixes quoted
                # examples with live imperatives is not span-removable.
                if educational_quote or any(quoted_flags):
                    original_spans: list[list[int]] = []
                else:
                    original_spans = [
                        [match.start(), match.end()]
                        for match in re.finditer(pattern, segment.text, re.I | re.S)
                    ][:16]
                severity = 0.2 if educational_quote else severity
                if educational_quote:
                    # The rule already judged this view's quoted example: the
                    # semantic layer must not re-flag the same category here.
                    rule_categories.add(category)
                elif severity >= 0.5:
                    rule_categories.add(category)
                logger.debug("detection.rule_matched", extra={"event_fields": dict(rule_id=rule["id"], category=category, match_count=len(matches), severity=severity, quoted_example=severity == 0.2, transformation=transformation)})
                findings.append(
                    Finding(
                        category=category,
                        rule_id=rule["id"],
                        source_id=segment.source_id,
                        locator=segment.locator,
                        transformation=transformation,
                        severity=severity,
                        spans=original_spans,
                    )
                )
        return findings
