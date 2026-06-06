# Security Policy

## ⚠️ Important Disclaimer

This MCP server provides AI tools with the ability to execute commands on servers, including potentially destructive operations. **Use at your own risk.**

The system is designed with the philosophy that **responsibility stays with the user**. While we provide safety mechanisms, they can be bypassed in FULL mode by design.

## Risk Levels

### 🟢 SAFE Mode (Low Risk)
- Read-only operations
- Docker container interaction (non-destructive)
- Log viewing and diagnostics
- No system modifications

### 🟡 PROVISION Mode (Medium Risk)
- Package installation
- Service configuration
- Docker/Nginx setup
- Firewall modifications
- **Requires explicit opt-in**
- **Time-limited (default: 1 hour)**

### 🔴 FULL Mode (High Risk)
- Unrestricted root access
- Any command can be executed
- Disk operations, system modifications
- **Requires explicit risk acknowledgement**
- **Time-limited (default: 30 minutes)**
- **All actions logged**

## Security Features

### Mode Enforcement
- Commands are validated against current mode allowlists
- Elevated modes require explicit acknowledgement
- All mode changes are logged

### Time-Limited Access
- PROVISION mode: 1 hour default
- FULL mode: 30 minutes default
- Automatic downgrade on expiry
- Sessions can be extended but require re-acknowledgement

### SSH Key Security
- Per-session SSH keys
- Automatic expiry
- Keys tagged with session ID for tracking
- Revocation commands provided

### Audit Logging
- All commands logged with timestamps
- Mode changes recorded
- SSH key lifecycle tracked
- Approval events logged
- Logs are immutable and JSON-formatted

### Command Validation
- SAFE mode: Allowlist-only execution
- Dangerous patterns detected and flagged
- Command chaining blocked unless FULL mode
- Sensitive data sanitized in logs

## Best Practices

### For Users

1. **Start in SAFE mode** - Only elevate when necessary
2. **Use time limits** - Don't leave elevated modes active
3. **Review commands** - Understand what AI is executing
4. **Check audit logs** - Regularly review actions taken
5. **Revoke SSH keys** - Clean up after sessions

### For Deployment

1. **Isolate target servers** - Don't use on production without safeguards
2. **Network segmentation** - Limit blast radius
3. **Backup systems** - Before running provisioning
4. **Monitor logs** - Set up alerting on suspicious activity
5. **Rotate credentials** - Regular key rotation

## What This System Does NOT Protect Against

- **User choosing FULL mode inappropriately**
- **AI making mistakes in FULL mode**
- **Malicious commands executed with user approval**
- **Data loss from destructive operations**
- **Network attacks on SSH connections**

## Vulnerability Reporting

If you discover a security vulnerability, please:

1. **Do not** open a public issue
2. Email security concerns to the maintainers
3. Provide detailed reproduction steps
4. Allow time for a fix before disclosure

## Threat Model

### In Scope
- Unauthorized mode elevation
- Command injection
- Log tampering
- SSH key leakage
- Session hijacking

### Out of Scope
- Physical access attacks
- AI model vulnerabilities
- Social engineering
- Denial of service

## Compliance Considerations

This system provides:
- **Audit trails** for compliance requirements
- **Access controls** with explicit permissions
- **Time-limited access** for principle of least privilege
- **Logging** for forensic investigation

However, it is the user's responsibility to ensure compliance with:
- Company security policies
- Industry regulations (SOC2, HIPAA, etc.)
- Data protection laws (GDPR, CCPA, etc.)

## Security Checklist

Before using in any environment:

- [ ] Understand the risk of each access mode
- [ ] Configure appropriate time limits
- [ ] Set up log monitoring
- [ ] Test in isolated environment first
- [ ] Document approved use cases
- [ ] Train users on proper usage
- [ ] Establish incident response procedures
