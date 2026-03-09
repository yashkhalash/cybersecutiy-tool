ISSUES_DATA = [
    {
        "id": "dependency_conflicts",
        "title": "Dependency Conflicts",
        "category": "Setup",
        "severity": "High",
        "description": "Incompatible versions of libraries causing build failures or runtime errors.",
        "symptoms": [
            "ImportError: cannot import name ...",
            "Version mismatch warnings during install",
            "Unexpected behavior in third-party modules"
        ],
        "resolution": "Use virtual environments (venv/conda) and lock files (requirements.txt/poetry.lock). Run `pip check` to find conflicts.",
        "prevention": "Stick to semantic versioning and regularly update dependencies in a controlled manner."
    },
    {
        "id": "env_config",
        "title": "Environment Variable Issues",
        "category": "Configuration",
        "severity": "Medium",
        "description": "Missing or incorrectly configured environment variables leading to 'None' values or connection failures.",
        "symptoms": [
            "KeyError when accessing os.environ",
            "Connection refused (wrong DB_HOST)",
            "Authentication failed (missing API_KEY)"
        ],
        "resolution": "Use a .env file and a loader like `python-dotenv`. Provide a .env.example template for other developers.",
        "prevention": "Implement a configuration validator that checks for required variables on startup."
    },
    {
        "id": "git_merge_conflicts",
        "title": "Git Merge Conflicts",
        "category": "Workflow",
        "severity": "Medium",
        "description": "Duplicate changes to the same lines of code preventing automatic merges.",
        "symptoms": [
            "CONFLICT (content): Merge conflict in file.py",
            "<<<<<<< HEAD markers in code"
        ],
        "resolution": "Use `git status` to find conflicts. Manually edit files, then `git add` and `git commit`.",
        "prevention": "Pull changes frequently. Keep pull requests small and focused."
    },
    {
        "id": "cors_policy",
        "title": "CORS Policy Blocks",
        "category": "Network",
        "severity": "High",
        "description": "Browser security blocking requests from the frontend to a different origin server.",
        "symptoms": [
            "Access to fetch at ... has been blocked by CORS policy",
            "No 'Access-Control-Allow-Origin' header present"
        ],
        "resolution": "Configure the backend to allow specific origins or use a proxy during development.",
        "prevention": "Establish clear CORS headers early in the API design phase."
    },
    {
        "id": "memory_leaks",
        "title": "Memory Leaks",
        "category": "Performance",
        "severity": "Critical",
        "description": "Application consumption of memory grows indefinitely, eventually leading to crashes.",
        "symptoms": [
            "Slow slow-down over time",
            "Out of Memory (OOM) errors",
            "High CPU usage during GC"
        ],
        "resolution": "Use memory profilers (e.g., `tracemalloc` in Python). Check for global variables and unclosed resources.",
        "prevention": "Use context managers (with statements) and avoid circular references."
    },
    {
        "id": "api_rate_limiting",
        "title": "API Rate Limiting",
        "category": "Integration",
        "severity": "Medium",
        "description": "Third-party APIs blocking requests due to exceeding quota limits.",
        "symptoms": [
            "HTTP 429 Too Many Requests",
            "Empty responses with long wait times"
        ],
        "resolution": "Implement exponential backoff and request throttling. Use caching where possible.",
        "prevention": "Monitor API usage and plan for higher tiers if needed. Use dev-keys for testing."
    },
    {
        "id": "async_race_conditions",
        "title": "Async Race Conditions",
        "category": "Logic",
        "severity": "High",
        "description": "Non-deterministic behavior caused by multiple async tasks accessing shared state.",
        "symptoms": [
            "Intermittent bugs",
            "Incorrect data in database",
            "UI state not matching model"
        ],
        "resolution": "Use locks/mutexes for shared resources. Ensure proper await/async flow.",
        "prevention": "Design stateless functions where possible. Avoid global mutable state in async apps."
    },
    {
        "id": "database_migrations",
        "title": "Broken DB Migrations",
        "category": "Database",
        "severity": "Critical",
        "description": "Database schema out of sync with application code.",
        "symptoms": [
            "Table not found error",
            "Column 'X' does not exist",
            "Migration script failed midway"
        ],
        "resolution": "Rollback if possible. Manually fix the schema or use a migration tool (Alembic/Prisma) to re-sync.",
        "prevention": "Always test migrations in a staging environment. Keep migrations idempotent."
    },
    {
        "id": "unhandled_exceptions",
        "title": "Unhandled Exceptions",
        "category": "Reliability",
        "severity": "High",
        "description": "Application crashes due to unexpected input or edge cases without try-catch blocks.",
        "symptoms": [
            "Process exited with non-zero code",
            "Stack trace shown to end-user"
        ],
        "resolution": "Add global error handlers. Use logging to capture the context of the crash.",
        "prevention": "Implement 'defensive programming' and validate all external inputs."
    },
    {
        "id": "broken_assets",
        "title": "Broken Asset Paths",
        "category": "Frontend",
        "severity": "Low",
        "description": "Images or scripts failing to load due to incorrect relative paths or build issues.",
        "symptoms": [
            "404 Not Found for .css or .js files",
            "Broken image icons"
        ],
        "resolution": "Verify paths relative to the build root. Use absolute paths or dynamic asset loaders.",
        "prevention": "Use consistent directory structures and automated build checks."
    }
]
