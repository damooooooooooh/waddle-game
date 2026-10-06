// Components of a typical LLM application, in data-flow order.
// Used for the "Decompose" phase of threat modeling: what are we building,
// what data moves through it, and where are the trust boundaries?
export const NODES = [
  {
    id: "user",
    label: "Chat UI",
    icon: "💬",
    desc: "Where people type prompts and read answers.",
    zone: "Untrusted",
    handles: "User prompts, pasted documents, session tokens",
  },
  {
    id: "orchestrator",
    label: "Orchestrator",
    icon: "🎛️",
    desc: "Builds the final prompt: system prompt, history, guardrails.",
    zone: "Trusted app tier",
    handles: "System prompt, conversation memory, API keys",
  },
  {
    id: "rag",
    label: "RAG / Vector DB",
    icon: "🗂️",
    desc: "Retrieves company knowledge and adds it to the prompt.",
    zone: "Mixed trust",
    handles: "Embeddings, indexed documents, tenant data",
  },
  {
    id: "model",
    label: "LLM Model",
    icon: "🧠",
    desc: "Hosted or self-hosted model, possibly fine-tuned.",
    zone: "Third-party / supply chain",
    handles: "Model weights, training data, completions",
  },
  {
    id: "tools",
    label: "Tools & Agents",
    icon: "🛠️",
    desc: "Plugins, MCP servers and APIs the model can call.",
    zone: "Privileged actions",
    handles: "OAuth tokens, email, files, databases, payments",
  },
  {
    id: "output",
    label: "Output Handler",
    icon: "📤",
    desc: "Renders or forwards the model's answer to people and systems.",
    zone: "Downstream consumers",
    handles: "HTML, Markdown, SQL, shell commands, published content",
  },
];
