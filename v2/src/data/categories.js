// OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
const LLM = {
  LLM01: {
    family: "llm",
    stride: ["T","E"],
    note: "Alteration of instructions. Elevation of Privilege when it drives privileged actions. Wrong Identity if it impersonates trusted content.",
    name: "Prompt Injection",
    color: "#ff2e93",
    icon: "💉",
    definition: "Prompts alter the model's behaviour in unintended ways, directly or through content it reads.",
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  },
  LLM02: {
    family: "llm",
    stride: ["I"],
    note: "",
    name: "Sensitive Information Disclosure",
    color: "#38bdf8",
    icon: "🔓",
    definition: "The model or its app exposes PII, secrets or proprietary data.",
    url: "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
  },
  LLM03: {
    family: "llm",
    stride: ["T","S"],
    note: "Altered models, datasets or plugins, with Wrong Identity in their claimed provenance.",
    name: "Supply Chain",
    color: "#f59e0b",
    icon: "📦",
    definition: "Compromised models, datasets, plugins or dependencies undermine the app.",
    url: "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
  },
  LLM04: {
    family: "llm",
    stride: ["T"],
    note: "",
    name: "Data and Model Poisoning",
    color: "#a855f7",
    icon: "☠️",
    definition: "Tampered training, fine-tuning or embedding data plants bias or backdoors.",
    url: "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
  },
  LLM05: {
    family: "llm",
    stride: ["T","E"],
    note: "Downstream injection or code execution.",
    name: "Improper Output Handling",
    color: "#ef4444",
    icon: "🧨",
    definition: "Model output is passed downstream without validation or sanitization.",
    url: "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
  },
  LLM06: {
    family: "llm",
    stride: ["E","R"],
    note: "Elevation of Privilege first, and Denial too when actions are not logged.",
    name: "Excessive Agency",
    color: "#f97316",
    icon: "🤖",
    definition: "The model has too much functionality, permission or autonomy.",
    url: "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
  },
  LLM07: {
    family: "llm",
    stride: ["I"],
    note: "",
    name: "System Prompt Leakage",
    color: "#22d3ee",
    icon: "📜",
    definition: "Secrets or rules in the system prompt are extracted by users.",
    url: "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
  },
  LLM08: {
    family: "llm",
    stride: ["I","T"],
    note: "Leakage across tenants, and Alteration through poisoned retrieval.",
    name: "Vector and Embedding Weaknesses",
    color: "#34d399",
    icon: "🧭",
    definition: "Weak access control or manipulated embeddings in RAG pipelines.",
    url: "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
  },
  LLM09: {
    family: "llm",
    stride: ["T"],
    note: "WADDLE fits this loosely. It is closer to an integrity or safety issue, so it is mapped to Alteration.",
    name: "Misinformation",
    color: "#facc15",
    icon: "🎭",
    definition: "Plausible but false output, such as hallucinations, drives bad decisions.",
    url: "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
  },
  LLM10: {
    family: "llm",
    stride: ["D"],
    note: "Also financial denial of wallet.",
    name: "Unbounded Consumption",
    color: "#fb7185",
    icon: "💸",
    definition: "Uncontrolled inference use causes denial of service, runaway cost or model theft.",
    url: "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
  },
};


// OWASP Top 10 for Agentic Applications (ASI, December 2025)
// https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
const ASI_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";
const ASI = {
  ASI01: {
    name: "Agent Goal Hijack", color: "#e11d6a", icon: "🎯", stride: ["T", "E"],
    note: "The agentic analog of LLM01.",
    definition: "Hidden instructions in content the agent reads redirect its goals, plans or actions.",
  },
  ASI02: {
    name: "Tool Misuse and Exploitation", color: "#fb923c", icon: "🔧", stride: ["E", "T"],
    note: "Also Disruption (runaway tool calls) and Leakage (data exfiltration via tools).",
    definition: "An agent uses a legitimate tool in an unsafe way: wrong arguments, runaway calls or data exfiltration.",
  },
  ASI03: {
    name: "Identity and Privilege Abuse", color: "#c084fc", icon: "🪪", stride: ["S", "E"],
    note: "The cleanest fit in the list.",
    definition: "Agents inherit, share or escalate credentials, so one agent acts with rights it should not have.",
  },
  ASI04: {
    name: "Agentic Supply Chain Vulnerabilities", color: "#eab308", icon: "🧩", stride: ["T", "S"],
    note: "Malicious tools, MCP servers and agent cards, which are Altered or pose as someone they are not.",
    definition: "Tools, MCP servers, prompts or agent cards loaded at runtime are malicious, tampered or spoofed.",
  },
  ASI05: {
    name: "Unexpected Code Execution", color: "#f43f5e", icon: "💣", stride: ["E", "T"],
    note: "",
    definition: "The agent generates or runs code and commands that reach the host or network.",
  },
  ASI06: {
    name: "Memory and Context Poisoning", color: "#8b5cf6", icon: "🧪", stride: ["T"],
    note: "Often persistent. Can lead to Leakage and Elevation of Privilege.",
    definition: "Bad data planted in memory, summaries or shared context keeps steering future decisions.",
  },
  ASI07: {
    name: "Insecure Inter-Agent Communication", color: "#2dd4bf", icon: "📡", stride: ["S", "T", "I"],
    note: "Wrong Identity through spoofed messages, Alteration and Leakage through intercepted ones.",
    definition: "Messages between agents are unauthenticated, unsigned or unencrypted, so they can be forged or read.",
  },
  ASI08: {
    name: "Cascading Failures", color: "#f87171", icon: "🌊", stride: ["D", "T"],
    note: "Disruption and Alteration propagating across agents.",
    definition: "One bad output or fault spreads agent to agent and amplifies into a system-wide failure.",
  },
  ASI09: {
    name: "Human-Agent Trust Exploitation", color: "#60a5fa", icon: "🎭", stride: ["S", "R"],
    note: "The agent is used to deceive the human approver, and the approval may not be attributable (Denial).",
    definition: "A convincing agent talks a person into approving something harmful, or the approval is not attributable.",
  },
  ASI10: {
    name: "Rogue Agents", color: "#a3e635", icon: "👻", stride: ["E", "T", "R"],
    note: "Misaligned or compromised behaviour, often with weak attribution (Denial).",
    definition: "An agent drifts or is compromised and acts outside its mandate, with no one able to tell.",
  },
};
for (const v of Object.values(ASI)) { v.family = "agentic"; v.url = ASI_URL; }

export const CATEGORIES = { ...LLM, ...ASI };
export const CATEGORY_IDS = Object.keys(CATEGORIES);
export const FAMILIES = {
  llm: { label: "OWASP Top 10 for LLM Applications 2025", short: "LLM Top 10", ids: Object.keys(LLM) },
  agentic: { label: "OWASP Top 10 for Agentic Applications (Dec 2025)", short: "Agentic Top 10", ids: Object.keys(ASI) },
};
// Distractors for "identify the risk" questions come from the same list as the answer.
export const sameFamily = (id) => FAMILIES[CATEGORIES[id].family].ids;

// STRIDE letters -> WADDLE letters (the v1 vocabulary).
export const STRIDE = {
  S: { name: "Spoofing", waddle: "W" },
  T: { name: "Tampering", waddle: "A" },
  R: { name: "Repudiation", waddle: "D2" },
  I: { name: "Information Disclosure", waddle: "L" },
  D: { name: "Denial of Service", waddle: "D1" },
  E: { name: "Elevation of Privilege", waddle: "E" },
};
export const WADDLE = {
  W: { letter: "W", name: "Wrong Identity", stride: "S", color: "#d946ef" },
  A: { letter: "A", name: "Alteration", stride: "T", color: "#f59e0b" },
  D1: { letter: "D", sub: "1", name: "Disruption", stride: "D", color: "#ef4444" },
  D2: { letter: "D", sub: "2", name: "Denial", stride: "R", color: "#fb923c" },
  L: { letter: "L", name: "Leakage of Information", stride: "I", color: "#38bdf8" },
  E: { letter: "E", name: "Elevation of Privilege", stride: "E", color: "#34d399" },
};
export const WADDLE_ORDER = ["W", "A", "D1", "D2", "L", "E"];
// First letter is the primary STRIDE category; the rest are secondary.
export const waddleOf = (catId) => CATEGORIES[catId].stride.map(s => STRIDE[s].waddle);

// The four-question model that every game phase is mapped to.
export const PHASES = [
  { id: "decompose", n: 1, question: "What are we working on?", label: "Decompose" },
  { id: "identify", n: 2, question: "What can go wrong?", label: "Identify" },
  { id: "mitigate", n: 3, question: "What are we going to do about it?", label: "Mitigate" },
  { id: "validate", n: 4, question: "Did we do a good enough job?", label: "Validate" },
];
