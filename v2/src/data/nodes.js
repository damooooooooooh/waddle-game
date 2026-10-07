// Components of a typical LLM application, in data-flow order.
// Used for the "Decompose" phase of threat modeling: what are we building,
// what data moves through it, and where are the trust boundaries?
const LLM_NODES = [
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

// Components of an autonomous agent, in the order a task flows through them.
const AGENT_NODES = [
  {
    id: "identity",
    label: "Agent Identity",
    icon: "🪪",
    desc: "The accounts, tokens and roles the agent acts as.",
    zone: "Credential boundary",
    handles: "Service accounts, delegated user tokens, API keys",
  },
  {
    id: "planner",
    label: "Agent Core",
    icon: "🎯",
    desc: "The planner that reads goals and content, then decides what to do next.",
    zone: "Mixed trust",
    handles: "Goals, plans, untrusted web pages, email and documents",
  },
  {
    id: "memory",
    label: "Memory & Context",
    icon: "🧪",
    desc: "Long-term memory, summaries and shared context the agent reuses.",
    zone: "Persistent state",
    handles: "Past conversations, learned preferences, cached facts",
  },
  {
    id: "atools",
    label: "Tools & MCP",
    icon: "🔧",
    desc: "MCP servers, APIs, shells and code runners the agent can use.",
    zone: "Privileged actions",
    handles: "Files, databases, payments, shell, third-party tool servers",
  },
  {
    id: "a2a",
    label: "Agent-to-Agent",
    icon: "📡",
    desc: "Messages and tasks passed between agents in a multi-agent system.",
    zone: "Internal network",
    handles: "Task requests, results, agent cards, shared state",
  },
  {
    id: "human",
    label: "Human Approver",
    icon: "🧑‍⚖️",
    desc: "The person who reviews, approves or overrides what the agent proposes.",
    zone: "Human oversight",
    handles: "Approval prompts, explanations, audit trail",
  },
];

export const TRACKS = {
  llm: { label: "LLM App", icon: "💬", blurb: "A chat assistant with RAG, a model, tools and rendered output.", nodes: LLM_NODES },
  agentic: { label: "Agentic System", icon: "🤖", blurb: "Autonomous agents with identity, memory, MCP tools, peers and human approvals.", nodes: AGENT_NODES },
};

export const NODES = [...LLM_NODES, ...AGENT_NODES]; // every node, for lookups by id
