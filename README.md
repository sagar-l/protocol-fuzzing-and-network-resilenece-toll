# FuzzStrike — Distributed Protocol Fuzzing & Network Resilience Tool

> A production-grade distributed system for generating malformed network payloads,
> firing them asynchronously at isolated targets, and capturing crash telemetry in real-time.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    FuzzStrike Architecture                       │
│                                                                  │
│  ┌─────────────┐    REST API    ┌─────────────────────┐         │
│  │  Dashboard   │◄─────────────►│  C2 Orchestrator    │         │
│  │  (Module D)  │   WebSocket   │  (Module A)         │         │
│  │  HTML/CSS/JS │               │  Python FastAPI      │         │
│  └─────────────┘               │  SQLite Persistence  │         │
│                                 └───────┬─────────────┘         │
│                                         │                        │
│                            Payload Batch│Dispatch                │
│                                         │                        │
│                                 ┌───────▼─────────────┐         │
│                                 │  Attack Node         │         │
│                                 │  (Module B)          │         │
│                                 │  Java 17 / Netty 4.1 │        │
│                                 └───────┬─────────────┘         │
│                                         │                        │
│                         Async TCP Flood │                        │
│                                         │                        │
│                                 ┌───────▼─────────────┐         │
│                                 │  Target Environment  │         │
│                                 │  (Module C)          │         │
│                                 │  Docker + Telemetry  │         │
│                                 └─────────────────────┘         │
└──────────────────────────────────────────────────────────────────┘
```

## Components

| Module | Name | Technology | Role |
|--------|------|------------|------|
| **A** | C2 Orchestrator | Python 3 / FastAPI / SQLite | Seed ingestion, mutation engine, campaign control |
| **B** | Attack Node | Java 17 / Netty 4.1 / Maven | High-throughput async TCP payload delivery |
| **C** | Target Environment | Docker / Python | Vulnerable target + crash telemetry agent |
| **D** | Dashboard | HTML / CSS / JS | Real-time Glassmorphism monitoring UI |

## Quick Start

```bash
# 1. Start the full stack
docker-compose up --build

# 2. Open the dashboard
open http://localhost:8080

# 3. The C2 API is available at
curl http://localhost:9000/docs
```

## Project Structure

```
jeevan/
├── docker-compose.yml              # Full-stack orchestration
├── c2-orchestrator/                 # Module A — The Brain
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py                  # FastAPI entry point
│       ├── config.py                # Centralized configuration
│       ├── database.py              # SQLite session management
│       ├── models.py                # SQLAlchemy ORM models
│       ├── mutator.py               # Payload mutation engine
│       └── routes/
│           ├── campaigns.py         # Campaign start/stop endpoints
│           ├── payloads.py          # Seed ingestion endpoints
│           └── telemetry.py         # Crash telemetry ingestion
├── attack-node/                     # Module B — The Muscle
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/java/com/fuzzstrike/attacknode/
│       ├── AttackNodeApplication.java
│       ├── client/
│       │   ├── NettyTcpClient.java
│       │   └── PayloadDispatcher.java
│       ├── handler/
│       │   ├── AttackChannelHandler.java
│       │   └── ResponseCollector.java
│       ├── model/
│       │   ├── PayloadBatch.java
│       │   └── AttackResult.java
│       └── service/
│           └── C2ApiClient.java
├── target-env/                      # Module C — The Eye
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── target_server.py
│   └── agent.py
└── dashboard/                       # Module D — The UI
    ├── index.html
    ├── css/style.css
    └── js/app.js
```

## License

MIT — For educational and authorized security testing purposes only.

Current Project Status
UI Enhancement: We are actively refining the user interface to improve real-time monitoring and user experience.

Stability & Bug Fixes: Ongoing efforts are focused on resolving known edge-case errors and optimizing network resilience.
