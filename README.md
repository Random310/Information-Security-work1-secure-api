# Work 1 - Secure REST API

This project is the starting point for Work 1: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis.

## Current state

The application currently provides:

- `GET /` - confirms that the API is running.
- `POST /auth/login` - verifies a bcrypt password and returns a JWT.
- `GET /api/data` - returns protected data only when a valid JWT is supplied.
- `POST /api/notes` - validates and escapes user text before storing it.

Users are stored in a local SQLite database through SQLAlchemy. Passwords are
stored only as bcrypt hashes. The security scanning pipeline and CVE analysis
will be added in later stages.

## Local setup

Create a virtual environment and install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start the application:

```powershell
.\.venv\Scripts\python.exe app.py
```

The direct start command keeps Flask debug mode disabled. This avoids exposing
the interactive development debugger.

Open <http://127.0.0.1:5000> or run:

```powershell
Invoke-RestMethod http://127.0.0.1:5000
```

## Create a local user

Stop the server before running this command. The password prompt hides the
password and asks you to confirm it:

```powershell
.\.venv\Scripts\python.exe -m flask --app app create-user student
```

The password must contain at least 8 bytes and no more than 72 bytes.

## Test login

Start the application, then use another PowerShell window:

```powershell
$loginBody = @{
    login = "student"
    password = "YOUR_PASSWORD"
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:5000/auth/login `
    -ContentType "application/json" `
    -Body $loginBody
```

A successful response contains an `access_token`. An incorrect password returns
HTTP status `401` with the same generic error used for an unknown user.

## Test the protected endpoint

Save the complete successful login response first:

```powershell
$response = Invoke-RestMethod `
    -Method Post `
    -Uri http://127.0.0.1:5000/auth/login `
    -ContentType "application/json" `
    -Body $loginBody
```

Send its token in the `Authorization` header:

```powershell
$headers = @{ Authorization = "Bearer $($response.access_token)" }
Invoke-RestMethod `
    -Method Get `
    -Uri http://127.0.0.1:5000/api/data `
    -Headers $headers
```

The request succeeds only with a valid token. Calling the same URL without the
`-Headers $headers` argument returns HTTP status `401`.

## Test input validation and XSS escaping

Submit a note containing a script element:

```powershell
$noteBody = @{ content = '<script>alert("XSS")</script>Hello' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/notes -Headers $headers -ContentType "application/json" -Body $noteBody | ConvertTo-Json -Depth 5
```

The response has HTTP status `201`, and its stored content contains escaped text
such as `&lt;script&gt;`. The script element is therefore treated as text rather
than executable HTML. Empty content, non-string content, and content over 500
characters return HTTP status `400`.

## Automated tests and security scans

Install the development tools and run the API test suite:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run the two security checks locally:

```powershell
.\.venv\Scripts\bandit.exe -r app.py models.py
.\.venv\Scripts\pip-audit.exe -r requirements.lock --no-deps --disable-pip -s osv --cache-dir .pip-audit-cache
```

The GitHub Actions workflow in `.github/workflows/security.yml` runs the tests,
Bandit SAST, and pip-audit SCA automatically for every push and pull request.
