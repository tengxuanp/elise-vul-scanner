Third-Party Labs

- DVWA: LAMP stack app for web vuln exercises
- OWASP Benchmark: Java/Servlet app for tool evaluation

Quickstart

- Start both: `make labs-up`
- Stop both: `make labs-down`
- Logs: `make labs-logs`

DVWA (LAMP/MySQL)

- Start only DVWA: `make dvwa-up`
- URL: `http://localhost:4280`
- First-time setup: if prompted, visit `/setup.php` and click “Create/Reset Database”
- Default login: `admin` / `password`

OWASP Benchmark (Java/Servlet)

- Start only Benchmark: `make benchmark-up`
- URL: `https://localhost:8443/benchmark/`
- Notes: self-signed certificate; your browser will show a warning. Continue/accept to proceed.
- First start can take several minutes (Maven build + Tomcat download)

Compose Details

- File: `labs/docker-compose.yml`
- DVWA ports: `4280 -> 80` (container)
- Benchmark ports: `8443 -> 8443` (HTTPS)

Cleanup

- Remove DVWA containers/volumes: `make dvwa-down`
- Remove both labs: `make labs-down`

Warnings

- These apps are intentionally vulnerable. Keep them on local/private networks only.
- Do not expose to the public internet.

