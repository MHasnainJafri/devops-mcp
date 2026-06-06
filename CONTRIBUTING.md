# Contributing to devops-mcp

Thank you for your interest in contributing! This document provides guidelines and standards for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd devops-mcp
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Build the project**
   ```bash
   npm run build
   ```

4. **Run in development mode**
   ```bash
   npm run dev
   ```

## Coding Standards

### TypeScript Guidelines

- Use strict TypeScript configuration
- Provide explicit types (avoid `any` where possible)
- Use interfaces for object shapes
- Use enums for fixed sets of values

### Code Style

- Use ESLint configuration provided
- 2 spaces for indentation
- Single quotes for strings
- Semicolons required
- Max line length: 100 characters

### Naming Conventions

- **Files**: kebab-case (`mode-manager.ts`)
- **Classes**: PascalCase (`ModeManager`)
- **Functions/Methods**: camelCase (`getCurrentMode`)
- **Constants**: UPPER_SNAKE_CASE (`ACCESS_MODE`)
- **Interfaces**: PascalCase with `I` prefix optional

### Documentation

- JSDoc comments for public APIs
- Inline comments for complex logic
- Update README for new features
- Update SECURITY.md for security-related changes

## Project Structure

```
src/
├── index.ts              # Entry point - minimal, delegates to modules
├── types/                # All type definitions
│   ├── index.ts          # Main types
│   └── errors.ts         # Custom error classes
├── core/                 # Core business logic
│   ├── index.ts          # Module exports
│   ├── logger.ts         # Logging system
│   ├── mode-manager.ts   # Access mode control
│   ├── command-validator.ts
│   ├── ssh-key-manager.ts
│   └── approval-manager.ts
├── executors/            # Command execution
│   ├── index.ts
│   ├── base-executor.ts  # Abstract base
│   ├── local-executor.ts
│   ├── ssh-executor.ts
│   └── docker-executor.ts
├── playbooks/            # Provisioning playbooks
│   ├── index.ts
│   ├── playbook-runner.ts
│   └── system-playbooks.ts
└── tools/                # MCP tool definitions
    ├── index.ts
    ├── tool-schemas.ts   # Zod schemas
    └── tool-handlers.ts  # Implementations
```

## Adding New Features

### Adding a New Tool

1. **Define the schema** in `src/tools/tool-schemas.ts`:
   ```typescript
   export const MyNewToolSchema = z.object({
     param1: z.string().describe('Description'),
     param2: z.number().optional(),
   });
   ```

2. **Add to TOOL_DEFINITIONS** in the same file:
   ```typescript
   {
     name: 'my_new_tool',
     description: 'What the tool does',
     inputSchema: MyNewToolSchema,
   }
   ```

3. **Implement handler** in `src/tools/tool-handlers.ts`:
   ```typescript
   export async function handleMyNewTool(
     input: z.infer<typeof schemas.MyNewToolSchema>
   ): Promise<MCPToolResponse> {
     // Implementation
   }
   ```

4. **Register handler** in TOOL_HANDLERS map

5. **Add tests** in `tests/tools/my-new-tool.test.ts`

### Adding a New Playbook

1. **Define in** `src/playbooks/system-playbooks.ts`:
   ```typescript
   export const myNewPlaybook: Playbook = {
     id: 'my-new-playbook',
     name: 'My New Playbook',
     description: 'What it does',
     requiredMode: AccessMode.PROVISION,
     steps: [
       // Steps
     ],
   };
   ```

2. **Add to ALL_PLAYBOOKS** array

3. **Export from** `src/playbooks/index.ts`

### Adding a New Executor

1. **Create file** `src/executors/my-executor.ts`

2. **Extend BaseExecutor**:
   ```typescript
   export class MyExecutor extends BaseExecutor {
     protected async doExecute(request: CommandRequest): Promise<CommandResult> {
       // Implementation
     }

     async testConnection(): Promise<boolean> {
       // Implementation
     }

     async cleanup(): Promise<void> {
       // Implementation
     }
   }
   ```

3. **Export from** `src/executors/index.ts`

4. **Update createExecutor factory** if needed

## Security Guidelines

### Critical Rules

1. **Never bypass mode checks** - Mode enforcement is security-critical
2. **Log everything** - All commands, mode changes, key events
3. **Validate all input** - Use Zod schemas, sanitize commands
4. **Time-limit elevated access** - No permanent FULL mode
5. **Sanitize logs** - Remove passwords, keys, secrets

### Code Review Checklist

- [ ] Mode checks in place for restricted operations
- [ ] Audit logging added for new operations
- [ ] Input validation using Zod schemas
- [ ] Error handling doesn't leak sensitive info
- [ ] No hardcoded credentials or secrets
- [ ] Tests cover security-critical paths

## Testing

### Running Tests

```bash
npm test           # Run all tests
npm run test:run   # Run once (CI mode)
```

### Test Requirements

- Unit tests for all core modules
- Integration tests for tool handlers
- Security tests for mode enforcement
- Mock external dependencies (SSH, Docker)

### Test Structure

```
tests/
├── core/
│   ├── mode-manager.test.ts
│   ├── command-validator.test.ts
│   └── ...
├── executors/
│   └── ...
├── tools/
│   └── ...
└── integration/
    └── ...
```

## Pull Request Process

1. **Create a branch** from `main`
2. **Make changes** following guidelines
3. **Write/update tests**
4. **Update documentation**
5. **Run linting**: `npm run lint`
6. **Run tests**: `npm test`
7. **Submit PR** with clear description

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Security Impact
- [ ] No security impact
- [ ] Security enhancement
- [ ] Requires security review

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No sensitive data in commits
```

## Release Process

1. Update version in `package.json`
2. Update CHANGELOG.md
3. Create release tag
4. Build and publish

## Questions?

Open an issue for questions or discussions about contributing.
