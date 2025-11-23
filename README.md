# MS1 - Users Microservice (FastAPI)

This repository contains a minimal FastAPI microservice implementing the Users service (MS1)
with registration, login (JWT), profile read/update, and soft-delete.

### Structure
See project files for implementation details.

### Quick start (local)
1. Create a Python virtualenv and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Prepare a MySQL database and update `DATABASE_URL` in `.env` or environment.
3. Run:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
4. API docs: http://localhost:8000/docs

