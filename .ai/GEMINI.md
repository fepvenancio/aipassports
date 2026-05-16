# AI Passport Architectural Rules

- Enforce strict Domain-Driven Design (DDD). The Domain layer must have zero external dependencies or framework imports.
- Use explicit native ES Modules (`import`/`export`).
- Every IO workflow must be wrapped in clean, asynchronous try/catch blocks.
- Skills must follow the `agentskills.io` layout inside `/skills`.
- Knowledge must follow the `LLM Wiki v2` markdown structure with YAML frontmatter inside `/wiki`.