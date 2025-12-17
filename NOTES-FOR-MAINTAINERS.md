# Notes for Maintainers

This document contains important information for future maintainers of this teaching repository.

## Architecture Design Decisions

### Directory Naming Strategy

Current structure:
- `backend/` - Vulnerable version (main teaching target)
- `backend-log4shell/` - CVE-2021-44228 demonstration
- `common/` - Shared models, DTOs, repositories

**Future expansion for secure version:**
- Reserve `backend-secure/` for the secure implementation
- Both versions should share the `common/` module
- Port 8082 is reserved for the secure backend

### Pre-configured Expansion Points

1. **Frontend Environment Variables**
   - `.env` file supports `VITE_API_BASE_URL`
   - Default: `/api/vulnerable`
   - For secure version: `/api/secure`
   - Students can modify `.env` to switch between versions

2. **Docker Compose Expansion**
   ```yaml
   # Add this service for secure version
   backend-secure:
     build:
       context: .
       dockerfile: docker/Dockerfile.backend-secure
     container_name: vuln-backend-secure
     environment:
       DB_HOST: postgres
       DB_PORT: 5432
       DB_NAME: owasp_demo
       DB_USER: postgres
       DB_PASSWORD: postgres
     ports:
       - "8082:8082"
     depends_on:
       postgres:
         condition: service_healthy
     networks:
       - app-network
   ```

3. **Nginx Proxy Expansion**
   Add to `docker/nginx.conf`:
   ```nginx
   location /api/secure/ {
       rewrite ^/api/secure/(.*)$ /api/$1 break;
       proxy_pass http://backend-secure:8082;
       proxy_http_version 1.1;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
   }
   ```

## Controller Mapping

Each vulnerable controller has a corresponding secure implementation pattern:

| Vulnerable Controller | Key Vulnerabilities | Secure Fix Approach |
|----------------------|---------------------|---------------------|
| AuthController | SQL injection, no rate limiting, account enumeration | Parameterized queries, rate limiting, generic error messages |
| AdminController | Missing authorization, IDOR | @PreAuthorize annotations, ownership verification |
| FileController | Path traversal | Path canonicalization, whitelist validation |
| SearchController | SQL injection | JPA Criteria API, input validation |
| SystemController | Command injection | Avoid Runtime.exec, whitelist commands |
| TemplateController | Expression injection | Disable dangerous features, sandbox |
| OrderController | IDOR, price manipulation | Ownership checks, server-side pricing |
| CryptoController | Weak algorithms (MD5, DES) | BCrypt, AES-256-GCM |
| WebhookController | SSRF | URL validation, allowlist |
| XmlController | XXE | Disable external entities |
| IntegrityController | Deserialization, mass assignment | Type whitelisting, DTO pattern |
| FlashSaleController | Race conditions | Database locks, atomic operations |
| CouponController | Logic bypass | Server-side validation |

## Database Schema Notes

- Both vulnerable and secure versions share the same database schema
- The `users` table stores plaintext passwords for the vulnerable version
- For secure version, implement BCrypt password encoding
- Consider adding a `password_hash` column or using environment-based password encoding

## Security Configuration Differences

### Vulnerable Version (`SecurityConfig.java`)
- CSRF disabled
- CORS allows all origins (`*`)
- NoOpPasswordEncoder (plaintext)
- All endpoints publicly accessible
- Actuator endpoints exposed

### Secure Version (to implement)
- CSRF enabled with proper token handling
- CORS restricted to specific origins
- BCryptPasswordEncoder
- Role-based access control (@PreAuthorize)
- Actuator endpoints protected or disabled

## Suggested Learning Flow

1. **Phase 1: Discovery**
   - Students read vulnerable code
   - Identify potential security issues

2. **Phase 2: Exploitation**
   - Manual testing to confirm vulnerabilities
   - Document findings

3. **Phase 3: Remediation**
   - Students implement fixes in a branch
   - Reference secure patterns (if available)

4. **Phase 4: Verification**
   - Run `scripts/verify-fix.sh` (to be implemented)
   - Confirm vulnerabilities are resolved

## Reference Materials

The original project (`../`) contains:
- `backend-secure/` - Complete secure implementation
- `docs/` - Detailed documentation
- `scripts/a01/` through `scripts/a10/` - Exploit scripts by OWASP category
- `zap-reports/` - DAST scan results
- `sonar-reports/` - SAST scan results

## Dependencies to Monitor

### Known Vulnerable Dependencies (Intentional)

| Dependency | Version | CVE | Purpose |
|------------|---------|-----|---------|
| Log4j | 2.14.1 | CVE-2021-44228 | Log4Shell demo |
| Commons Collections | 4.0 | Deserialization gadgets | A08 demo |

### Dependencies to Keep Updated

- Spring Boot (except for intentional vulnerabilities)
- PostgreSQL driver
- Frontend packages

## Testing the Secure Version

When implementing the secure version:

1. All original functionality should work
2. Vulnerabilities should be mitigated
3. Run comparison tests:
   ```bash
   # Test vulnerable endpoint
   curl -X POST http://localhost:8081/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' OR 1=1--","password":"x"}'
   
   # Same test on secure endpoint should fail safely
   curl -X POST http://localhost:8082/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' OR 1=1--","password":"x"}'
   ```

## Environment Variables

### Current
| Variable | Default | Description |
|----------|---------|-------------|
| DB_HOST | postgres | Database host |
| DB_PORT | 5432 | Database port |
| DB_NAME | owasp_demo | Database name |
| DB_USER | postgres | Database user |
| DB_PASSWORD | postgres | Database password |

### Reserved for Secure Version
| Variable | Suggested | Description |
|----------|-----------|-------------|
| JWT_SECRET | (generate) | Strong JWT signing key (32+ chars) |
| BCRYPT_ROUNDS | 12 | BCrypt cost factor |
| CORS_ORIGINS | http://localhost | Allowed CORS origins |
| RATE_LIMIT | 100 | Requests per minute |

## Verification Script Placeholder

The `scripts/verify-fix.sh` should:
1. Run a series of attack payloads
2. Verify vulnerable version is exploitable
3. Verify secure version blocks attacks
4. Generate a comparison report

Example structure:
```bash
#!/bin/bash
# scripts/verify-fix.sh

echo "Testing SQL Injection..."
# Test vulnerable
VULN_RESULT=$(curl -s -X POST http://localhost:8081/api/auth/login ...)
# Test secure
SEC_RESULT=$(curl -s -X POST http://localhost:8082/api/auth/login ...)

# Compare and report
```

## Contact

For questions about the original implementation, refer to the parent project documentation.
