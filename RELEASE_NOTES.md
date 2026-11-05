## MacSec 0.8.0

### Free LLM API
Connect Free LLM API on the Tools page: paste its unified key once (it goes to the Keychain) and Claude Code reviews can run on every free key you added to it (Google AI Studio, Groq, NVIDIA, OpenRouter and more). Choose “Claude Code on Free LLM API” when you start a review, next to your Claude account and LM Studio. Pick auto (your routing chain), auto:fast or one model. The key is hidden in MacSec's logs.

### Skills from Cloudflare and Anthropic
Two more skill sets on the Tools page:
- **Cloudflare's security audit**: reconnaissance, hunting by attack class (web and sign-in, client side, cloud, data isolation, supply chain, AI apps, desktop and local IPC, protocols, memory safety, resource exhaustion) and checked findings with evidence.
- **Anthropic's /security-review**: a senior engineer's review of your changes that reports only high-confidence problems. It becomes a skill for reviews and stays a /security-review command in Claude Code.

