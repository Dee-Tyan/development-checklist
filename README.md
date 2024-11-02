# Application Security Checklist
## To help you secure your application effectively, here’s a practical checklist that covers essential security controls and best practices. Use this list as a guide to build a secure, resilient application by anticipating potential vulnerabilities and incorporating proactive measures into your development workflow.

### Broken Access Control Prevention Checklist

- [ ] All resources are denied by default, except those explicitly marked as public.
- [ ] MFA is required for all sensitive user actions (e.g., login, password changes, transactions).
- [ ] Support for multiple authentication factors (e.g., OTP via SMS, email, and authenticator apps) is provided.
- [ ] Access control mechanisms are implemented centrally and reused across the entire application.
- [ ] CORS usage is minimized and restricted to only essential cases.
- [ ] Access control mechanisms enforce record ownership for all CRUD operations.
- [ ] Users can only perform actions (create, read, update, delete) on records they own.
- [ ] URLs and query parameters are checked against user authorization levels, ensuring users can't access resources they shouldn't.
- [ ] Unique business logic rules are enforced at the domain model level.
- [ ] Business logic limits are consistently applied across the application.
- [ ] Web server directory listing is disabled.
- [ ] All URLs and query parameters are validated server-side to prevent tampering.
- [ ] Sensitive files (e.g., .git, backup files) are not present within the web root.
- [ ] All-access control failures are logged.
- [ ] Administrators are alerted when repeated access control failures occur.
- [ ] Rate limiting is applied to API and controller access.
- [ ] Rate limits are reviewed and adjusted regularly.
- [ ] Stateful session identifiers are invalidated on the server upon user logout.
- [ ] JWT tokens are short-lived to minimize the attack window.
- [ ] OAuth standards are followed for revoking access on longer-lived JWT tokens.

### Cryptographic Failures Prevention Checklist

- [ ] Input sanitization is performed on query parameters to prevent injection attacks (e.g., SQL injection, XSS).
- [ ] Data has been classified based on the type processed, stored, or transmitted by the application.
- [ ] Sensitive data has been identified in accordance with privacy laws, regulatory requirements, or business needs.
- [ ] Sensitive data is not stored unnecessarily and is discarded as soon as possible.
- [ ] PCI DSS compliant tokenization or truncation is used for sensitive data.
- [ ]  All sensitive data is encrypted at rest using an obfuscator.
- [ ]  Strong, up-to-date algorithms, protocols, and key management are in place.
- [ ]  All data in transit is encrypted using TLS, and HTTP Strict Transport Security (HSTS) is enforced.
- [ ]  Caching is disabled for responses that contain sensitive data.
- [ ]  Security controls are applied according to the data classification.
- [ ]  Legacy protocols (e.g., FTP, SMTP) are not used for transporting sensitive data.
- [ ]  Passwords are stored using strong, adaptive, and salted hashing functions like Argon2, bcrypt, or PBKDF2.
- [ ]  Initialization vectors (IVs) are generated using CSPRNG where necessary and are never reused for a fixed key.
- [ ]  Authenticated encryption is used instead of basic encryption.
- [ ]  Cryptographic keys are generated using secure randomness and stored as byte arrays.
- [ ]  Cryptographic randomness is used properly, with no predictable seeding.
- [ ]  Deprecated cryptographic functions (e.g., MD5, SHA1) and padding schemes (e.g., PKCS #1 v1.5) are avoided.
- [ ]  Cryptographic configurations and settings are independently verified for effectiveness.

### Injection Attacks Prevention Checklist

- [ ]  Input sanitization is performed on query parameters to prevent injection attacks (e.g., SQL injection, XSS).
- [ ]  Object Relational Mapping Tools (ORMs) have been implemented where possible.
- [ ]  Stored procedures do not concatenate queries and data, and unsafe functions like EXECUTE IMMEDIATE or exec() are avoided.
- [ ]  Positive server-side input validation is in place.
- [ ]  Special characters in dynamic queries are escaped using the specific syntax for the interpreter.
- [ ]  User-supplied structure names, such as table or column names, are avoided.
- [ ]  LIMIT and other SQL controls are used to prevent mass disclosure of records.
- [ ]  Avoid user-supplied structure names (e.g., table names, column names) as they cannot be safely escaped.
- [ ]  Use LIMIT and other SQL controls to restrict data exposure in case of SQL injection.


### Insecure Design Prevention Checklist

- [ ]  A library of secure design patterns or ready-to-use components (paved road) is in place and used.
- [ ]  Threat modeling is performed for critical authentication, access control, business logic, and key flows.
- [ ]  Security language and controls are integrated into user stories.
- [ ]  Plausibility checks are integrated at each tier of the application, from frontend to backend.
- [ ]  Unit and integration tests are written to validate that all critical flows are resistant to the threat model.
- [ ]  Use-cases and misuse-cases are compiled for each tier of the application.
- [ ]  Tier layers are segregated at the system and network layers based on exposure and protection needs.
- [ ]  Tenants are segregated robustly by design across all tiers.
- [ ]  Resource consumption is limited by user or service to prevent abuse.


### Security Misconfiguration Prevention Checklist

- [ ]  A repeatable hardening process is in place to deploy secure environments quickly and consistently across Development, QA, and Production, with different credentials used in each.
- [ ]  The environment is minimal, with no unnecessary features, components, documentation, or samples installed.
- [ ]  Configurations are regularly reviewed and updated as part of the patch management process, including security notes, updates, and cloud storage permissions (e.g., S3).
- [ ]  A segmented application architecture is implemented, ensuring secure separation between components or tenants using segmentation, containerization, or cloud security groups (ACLs).
- [ ]  Security directives, such as security headers, are sent to clients.
An automated process is in place to verify the effectiveness of configurations and settings across all environments.

### Vulnerable and Outdated Components Prevention Checklist

- [ ]  Unused dependencies, unnecessary features, components, files, and documentation have been removed.
- [ ]  Client-side and server-side components and their dependencies are continuously inventoried and tracked using tools (e.g., OWASP Dependency Check, retire.js).
- [ ]  Sources like Common Vulnerability and Exposures (CVE) and National Vulnerability Database (NVD) are continuously monitored for vulnerabilities in components.
- [ ]  Software composition analysis tools are used to automate the process of tracking and updating component versions.
- [ ]  Security vulnerability email alerts for components used in the application are subscribed to and monitored.
- [ ]  Components are only obtained from official sources over secure links, and signed packages are preferred to reduce the risk of including malicious components.
- [ ]  Libraries and components are monitored for maintenance and security patches, and unmaintained components are addressed.
- [ ]  Virtual patches are deployed to monitor, detect, or protect against issues in cases where patching a component is not possible.

### Identification and Authentication Failures Prevention Checklist

- [ ]  Multi-factor authentication (MFA) is implemented where possible to prevent automated credential stuffing, brute force, and stolen credential reuse attacks.
- [ ]  Default credentials, particularly for admin users, are removed before shipping or deploying the application.
- [ ]  Weak password checks are in place, such as testing new or changed passwords against the top 10,000 worst passwords list.
- [ ]  Password length, complexity, and rotation policies align with NIST 800-63b guidelines in section 5.1.1 for Memorized Secrets or other modern, evidence-based password policies.
- [ ]  Registration, credential recovery, and API pathways are hardened against account enumeration attacks by using consistent messages for all outcomes.
- [ ]  Failed login attempts are limited or increasingly delayed, with precautions to avoid denial of service scenarios. All failures are logged, and administrators are alerted when credential stuffing, brute force, or similar attacks are detected.
- [ ]  A secure, server-side session manager is used, generating a new random session ID with high entropy after login. The session identifier is not included in the URL, is securely stored, and is invalidated after logout, idle, and absolute timeouts.

### Software and Data Integrity Prevention Checklist

- [ ]  Digital signatures or similar mechanisms are used to verify that the software or data is from the expected source and has not been altered.
- [ ]  Libraries and dependencies (e.g., npm or Maven) are sourced from trusted repositories, or a vetted internal known-good repository is hosted if there is a higher risk profile.
- [ ]  A software supply chain security tool, such as OWASP Dependency Check or OWASP CycloneDX, is used to verify that components do not contain known vulnerabilities.
- [ ]  There is a review process in place for code and configuration changes to minimize the risk of malicious code or configurations being introduced into the software pipeline.
- [ ]  The CI/CD pipeline is properly segregated, configured, and access-controlled to ensure the integrity of the code throughout the build and deploy processes.
- [ ]  Unsigned or unencrypted serialized data is not sent to untrusted clients without an integrity check or digital signature to detect tampering or replay of the serialized data.

### Security Logging and Monitoring Failures Prevention Checklist

- [ ]  All login, access control, and server-side input validation failures are logged with sufficient user context to identify suspicious or malicious accounts, and logs are retained long enough for delayed forensic analysis.
- [ ]  Logs are generated in a format that log management solutions can easily consume.
- [ ]  Log data is correctly encoded to prevent injections or attacks on logging or monitoring systems.
- [ ]  High-value transactions have an audit trail with integrity controls, such as append-only database tables, to prevent tampering or deletion.
- [ ]  Effective monitoring and alerting are in place to detect and respond to suspicious activities quickly.
- [ ]  An incident response and recovery plan (e.g., NIST 800-61r2 or later) is established or adopted.

### Server-Side Request Forgery Prevention Checklist

- [ ]  All client-supplied input data is sanitized and validated.
- [ ]  URL schema, port, and destination are enforced with a positive allow list.
- [ ]  Raw responses are not sent back to clients.
- [ ]  HTTP redirections are disabled.
- [ ]  URL consistency is checked to avoid attacks such as DNS rebinding and TOCTOU race conditions.
- [ ]  Deny lists or regular expressions are not used to mitigate SSRF, as attackers can bypass these protections.
- [ ]  No other security-relevant services (e.g., OpenID) are deployed on front systems.
- [ ]  Local traffic is controlled on systems like localhost.

