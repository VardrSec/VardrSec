"""Least-privilege PostgreSQL application role for the Compose installation (issue #52).

`vardrmap` stays the administrative account; it is used only inside the database
container (socket) by this module and by backup and restore. The API connects as
`vardrmap_app`: a plain login role that owns the application schema and runs the
unchanged startup migrations, with no SUPERUSER, CREATEDB, CREATEROLE, REPLICATION
or BYPASSRLS. Every mutation is one transaction, idempotent, and never prints, logs
or passes a password on a command line.
"""

import base64
import contextlib
import hashlib
import hmac
import os
import re
import secrets
import subprocess

import recovery

ADMIN = "vardrmap"
APP = "vardrmap_app"
DATABASE = "vardrmap"
PASSWORD_NAME = "POSTGRES_APP_PASSWORD"
PASSWORD_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,128}")
FLAGS = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")
OBJECT_KINDS = "('r','p','v','m','f')"

# Applied by the administrative account over the container's local socket, on stdin.
# The only secret it carries is a SCRAM verifier, never the password, and statement
# logging of errors is switched off for the session. BEGIN/COMMIT make failure
# all-or-nothing: ON_ERROR_STOP ends the session, which rolls the transaction back.
ROLE_SQL = """\\set ON_ERROR_STOP on
SET log_min_error_statement = panic;
BEGIN;
DO $role$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vardrmap_app') THEN
    CREATE ROLE vardrmap_app LOGIN;
  END IF;
END
$role$;
ALTER ROLE vardrmap_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '__VERIFIER__';
DO $connect$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO vardrmap_app', current_database());
END
$connect$;
GRANT USAGE, CREATE ON SCHEMA public TO vardrmap_app;
DO $ownership$
DECLARE item record;
BEGIN
  FOR item IN
    SELECT n.nspname, c.relname, c.relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relowner <> 'vardrmap_app'::regrole
      AND (c.relkind IN ('r','p','v','m','f')
           OR (c.relkind = 'S' AND NOT EXISTS (
                 SELECT FROM pg_depend d
                 WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                   AND d.deptype IN ('a','i'))))
  LOOP
    EXECUTE format('ALTER %s %I.%I OWNER TO vardrmap_app',
      CASE item.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                        WHEN 'f' THEN 'FOREIGN TABLE' WHEN 'S' THEN 'SEQUENCE'
                        ELSE 'TABLE' END,
      item.nspname, item.relname);
  END LOOP;
END
$ownership$;
"""
ROLE_SQL_END = "COMMIT;\n"

STATE_QUERY = f"""SELECT
  (SELECT count(*) FROM pg_roles WHERE rolname = '{APP}'),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN {OBJECT_KINDS}),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN {OBJECT_KINDS}
       AND pg_get_userbyid(c.relowner) <> '{APP}')"""

# Run over TCP as the application role, so this proves the password and scram
# authentication rather than the container's trusted local socket.
CHECK_QUERY = f"""SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
  r.rolbypassrls,
  (SELECT count(*) FROM pg_auth_members WHERE member = r.oid),
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN {OBJECT_KINDS} AND c.relowner <> r.oid),
  current_user
FROM pg_roles r WHERE r.rolname = current_user"""


def scram_verifier(password, salt=None, iterations=4096):
    """A PostgreSQL SCRAM-SHA-256 verifier, so the password itself never reaches SQL."""
    salt = os.urandom(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    stored = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
    server = hmac.new(salted, b"Server Key", "sha256").digest()
    encode = lambda value: base64.b64encode(value).decode()  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored)}:{encode(server)}"


def role_sql(password, trailer=""):
    return ROLE_SQL.replace("__VERIFIER__", scram_verifier(password)) + trailer + ROLE_SQL_END


def check_password(value):
    if not PASSWORD_PATTERN.fullmatch(value or ""):
        raise ValueError(
            f"{PASSWORD_NAME} must be 32-128 letters, digits, '-' or '_'; "
            "fix it in .env without printing it"
        )
    return value


def parse_password(text):
    """The application password in .env text, or None when it has never been set."""
    found = None
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip() == PASSWORD_NAME:
            found = value.strip()
    return None if found is None else check_password(found)


def read_password(root):
    path = root / ".env"
    if not path.exists():
        raise ValueError("No .env found. Run python3 vardrsec.py configure first")
    return parse_password(path.read_text(encoding="utf-8"))


def append_password(root, password):
    """Add the new credential to .env; an existing value is never rewritten."""
    path = root / ".env"
    existing = path.read_bytes()
    prefix = b"" if not existing or existing.endswith(b"\n") else b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    with os.fdopen(descriptor, "ab") as output:
        output.write(prefix + f"{PASSWORD_NAME}={password}\n".encode())


@contextlib.contextmanager
def credential(password):
    """Expose the password to child processes only, so Compose can resolve its files."""
    previous = os.environ.get(PASSWORD_NAME)
    os.environ[PASSWORD_NAME] = password
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(PASSWORD_NAME, None)
        else:
            os.environ[PASSWORD_NAME] = previous


def redact(text):
    return re.sub(r"SCRAM-SHA-256\$\S+", "[verifier]", text or "")


def psql(root, project, *arguments, user=ADMIN, host=None, password=None, stdin=None):
    """Run psql in the database container; its stdout, or a ValueError without secrets."""
    options = ["-e", "PGPASSWORD"] if password is not None else []
    network = ["-h", host] if host else []
    environment = {**os.environ, "PGPASSWORD": password} if password is not None else None
    try:
        result = recovery.compose(
            root, "exec", "-T", *options, "db", "psql", "-X", "-w", *network,
            "-U", user, "-d", DATABASE, *arguments,
            project=project, input=stdin, env=environment,
            capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as error:
        lines = [l for l in redact(error.stderr).splitlines() if "ERROR:" in l or "FATAL:" in l]
        raise ValueError(
            "PostgreSQL rejected the request: " + (" ".join(lines[:2]) or "no detail")
        ) from None
    return result.stdout


def state(root, project):
    row = psql(root, project, "-At", "-F", "|", "-c", STATE_QUERY).strip().split("|")
    role, objects, foreign = (int(v) for v in row)
    return {"role": bool(role), "objects": objects, "foreign": foreign}


def require_stopped(root, project):
    running = set(
        recovery.compose(
            root, "ps", "--services", "--status", "running",
            project=project, capture_output=True, text=True,
        ).stdout.split()
    )
    active = sorted(running & {"api", "web", "proxy"})
    if active:
        raise ValueError(
            "Ownership of existing data must change with the application stopped; "
            f"stop {', '.join(active)} first (python3 vardrsec.py stop)"
        )


def require_current_backup(root, project, backup):
    if backup is None:
        raise ValueError(
            "This database holds data that is not yet owned by the application role. "
            "Take a backup with the current installation first (python3 vardrsec.py "
            "backup --destination DIR), then run database-role --backup DIR"
        )
    metadata = recovery.validate(backup.resolve())
    if metadata["database"] != recovery.database_fingerprint(root, project):
        raise ValueError(
            "The backup does not match the current database. Applications must stay "
            "stopped after the backup; take a new one and retry"
        )


def verify(root, project, password):
    """Log in as the application role over TCP and check it, without echoing anything else."""
    row = psql(
        root, project, "-At", "-F", "|", "-c", CHECK_QUERY,
        user=APP, host="db", password=password,
    ).strip().split("|")
    flags, memberships, foreign, user = row[:5], row[5], row[6], row[7]
    problems = []
    if user != APP:
        problems.append("unexpected login role")
    problems += [name for name, flag in zip(FLAGS, flags) if flag != "f"]
    if memberships != "0":
        problems.append("role memberships")
    if foreign != "0":
        problems.append("objects not owned by the application role")
    if problems:
        raise ValueError(
            "Application role verification failed (" + ", ".join(problems) + "); "
            "the database was not damaged, review before starting the applications"
        )


def apply(root, project=None, backup=None, restoring=False, trailer=""):
    """Create or reconcile the application role. Safe to repeat; fails closed."""
    password = read_password(root)
    generated = password is None
    password = check_password(secrets.token_hex(32)) if generated else password
    with credential(password):
        recovery.compose(root, "up", "-d", "--wait", "db", project=project)
        current = state(root, project)
        if current["foreign"] and not restoring:
            require_stopped(root, project)
            if current["objects"]:
                require_current_backup(root, project, backup)
        if generated:
            append_password(root, password)
        psql(root, project, "-f", "-", stdin=role_sql(password, trailer))
        verify(root, project, password)
    return {"created_password": generated, "reassigned": current["foreign"]}


def restore_role(root, project):
    """After pg_restore: hand restored (administrator-owned) data to the application role."""
    if read_password(root) is None:
        print(
            "Restored a pre-role configuration; it still uses the administrative account. "
            "Run python3 vardrsec.py database-role in that installation to upgrade it."
        )
        return
    apply(root, project, restoring=True)
