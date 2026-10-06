// OWASP Top 10 for LLM Applications 2025
// https://genai.owasp.org/llm-top-10/
export const CATEGORIES = {
  LLM01: {
    name: "Prompt Injection",
    color: "#ff2e93",
    icon: "💉",
    definition: "Prompts alter the model's behaviour in unintended ways, directly or through content it reads.",
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  },
  LLM02: {
    name: "Sensitive Information Disclosure",
    color: "#38bdf8",
    icon: "🔓",
    definition: "The model or its app exposes PII, secrets or proprietary data.",
    url: "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
  },
  LLM03: {
    name: "Supply Chain",
    color: "#f59e0b",
    icon: "📦",
    definition: "Compromised models, datasets, plugins or dependencies undermine the app.",
    url: "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
  },
  LLM04: {
    name: "Data and Model Poisoning",
    color: "#a855f7",
    icon: "☠️",
    definition: "Tampered training, fine-tuning or embedding data plants bias or backdoors.",
    url: "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
  },
  LLM05: {
    name: "Improper Output Handling",
    color: "#ef4444",
    icon: "🧨",
    definition: "Model output is passed downstream without validation or sanitization.",
    url: "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
  },
  LLM06: {
    name: "Excessive Agency",
    color: "#f97316",
    icon: "🤖",
    definition: "The model has too much functionality, permission or autonomy.",
    url: "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
  },
  LLM07: {
    name: "System Prompt Leakage",
    color: "#22d3ee",
    icon: "📜",
    definition: "Secrets or rules in the system prompt are extracted by users.",
    url: "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
  },
  LLM08: {
    name: "Vector and Embedding Weaknesses",
    color: "#34d399",
    icon: "🧭",
    definition: "Weak access control or manipulated embeddings in RAG pipelines.",
    url: "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
  },
  LLM09: {
    name: "Misinformation",
    color: "#facc15",
    icon: "🎭",
    definition: "Plausible but false output, such as hallucinations, drives bad decisions.",
    url: "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
  },
  LLM10: {
    name: "Unbounded Consumption",
    color: "#fb7185",
    icon: "💸",
    definition: "Uncontrolled inference use causes denial of service, runaway cost or model theft.",
    url: "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
  },
};

export const CATEGORY_IDS = Object.keys(CATEGORIES);

// The four-question model that every game phase is mapped to.
export const PHASES = [
  { id: "decompose", n: 1, question: "What are we working on?", label: "Decompose" },
  { id: "identify", n: 2, question: "What can go wrong?", label: "Identify" },
  { id: "mitigate", n: 3, question: "What are we going to do about it?", label: "Mitigate" },
  { id: "validate", n: 4, question: "Did we do a good enough job?", label: "Validate" },
];
