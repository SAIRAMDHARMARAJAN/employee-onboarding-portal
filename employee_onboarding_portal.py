import os
import re
import base64
import hashlib
import json
import secrets
from datetime import date, datetime

import streamlit as st
import pandas as pd
import snowflake.connector
from streamlit_autorefresh import st_autorefresh

from cryptography.hazmat.primitives import serialization
from email_validator import validate_email, EmailNotValidError
import phonenumbers

def load_local_env():
    env_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        ".env"
    )

    if not os.path.isfile(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            name, value = line.split("=", 1)
            os.environ.setdefault(name.strip(), value.strip().strip('"\''))


load_local_env()


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Employee Onboarding Portal",
    page_icon="🏢",
    layout="wide"
)


# ============================================================
# SNOWFLAKE CONFIGURATION
# ============================================================

DATABASE = os.environ.get("SNOWFLAKE_DATABASE", "EMP_DB")
SCHEMA = os.environ.get("SNOWFLAKE_SCHEMA", "INFO")
TABLE = os.environ.get("SNOWFLAKE_TABLE", "EMPLOYEE_ONBOARDING")
WAREHOUSE = os.environ.get("SNOWFLAKE_WAREHOUSE", "EMPLOYEE_WH")

FULL_TABLE = f"{DATABASE}.{SCHEMA}.{TABLE}"
FEATURE_SCHEMA = f"{DATABASE}.{SCHEMA}"
EDIT_REQUESTS_TABLE = f"{FEATURE_SCHEMA}.EMPLOYEE_EDIT_REQUESTS"
POLICY_ACK_TABLE = f"{FEATURE_SCHEMA}.EMPLOYEE_POLICY_ACKNOWLEDGMENTS"
MESSAGES_TABLE = f"{FEATURE_SCHEMA}.EMPLOYEE_MESSAGES"
SUPPORT_TABLE = f"{FEATURE_SCHEMA}.EMPLOYEE_SUPPORT_REQUESTS"

POLICIES = [
    ("code_of_conduct", "Code of Conduct", "1.0"),
    ("privacy", "Employee Privacy Policy", "1.0"),
    ("it_security", "IT Security Policy", "1.0")
]

# HR password is kept outside source code in the local environment file.
HR_PASSWORD = os.environ.get("HR_PASSWORD", "")


# ============================================================
# SESSION STATE
# ============================================================

if "portal" not in st.session_state:
    st.session_state.portal = "Employee Portal"

if "hr_logged_in" not in st.session_state:
    st.session_state.hr_logged_in = False

if "employee_logged_in" not in st.session_state:
    st.session_state.employee_logged_in = False

if "employee_id" not in st.session_state:
    st.session_state.employee_id = None

if "employee_edit_mode" not in st.session_state:
    st.session_state.employee_edit_mode = False

if "last_activity" not in st.session_state:
    st.session_state.last_activity = None


# ============================================================
# BASIC HELPERS
# ============================================================

def clean(value):
    if value is None:
        return ""

    return str(value).strip()


def required(value, field_name):

    value = clean(value)

    if not value:
        return False, f"{field_name} is required."

    return True, value


def mark_activity():
    st.session_state.last_activity = datetime.now()


def enforce_inactivity_timeout():

    if not (
        st.session_state.hr_logged_in
        or st.session_state.employee_logged_in
    ):
        return False

    last_activity = st.session_state.last_activity

    if last_activity is None:
        mark_activity()
        return False

    if (datetime.now() - last_activity).total_seconds() < 120:
        return False

    st.session_state.hr_logged_in = False
    st.session_state.employee_logged_in = False
    st.session_state.employee_id = None
    st.session_state.employee_edit_mode = False
    st.session_state.last_activity = None
    st.session_state.previous_refresh_count = None
    st.warning("You were logged out after 2 minutes of inactivity.")

    return True


def hash_password(password):

    salt = secrets.token_bytes(16) 
    digest = hashlib.pbkdf2_hmac(  
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return (
        "pbkdf2_sha256$600000$"
        f"{salt.hex()}${digest.hex()}"
    )


def verify_password(password, stored_hash):

    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations)
        )

        return secrets.compare_digest(
            digest.hex(),
            digest_hex
        )

    except (AttributeError, ValueError):
        return False


def validate_employee_password(password):

    if len(password) < 8:
        return False, "Employee password must contain at least 8 characters."

    return True, password


# ============================================================
# EMAIL VALIDATION
# ============================================================

def validate_email_address(email):

    email = clean(email).lower()

    if not email:
        return False, "Email is required."

    try:

        result = validate_email(
            email,
            check_deliverability=False
        )

        return True, result.normalized

    except EmailNotValidError:

        return False, "Please enter a valid email address."


# ============================================================
# PHONE VALIDATION
# ============================================================

def validate_phone_number(phone):

    phone = clean(phone)

    if not phone:
        return False, "Phone number is required."

    try:

        parsed = phonenumbers.parse(
            phone,
            "IN"
        )

        if not phonenumbers.is_possible_number(parsed):
            return False, "Phone number is not possible."

        if not phonenumbers.is_valid_number(parsed):
            return False, "Please enter a valid phone number."

        formatted = phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.E164
        )

        return True, formatted

    except phonenumbers.NumberParseException:

        return False, (
            "Invalid phone number. "
            "Use format such as +919876543210."
        )


# ============================================================
# NAME VALIDATION
# ============================================================

def validate_name(value, field_name):

    value = clean(value)

    if not value:
        return False, f"{field_name} is required."

    if len(value) < 2:
        return False, (
            f"{field_name} must contain at least 2 characters."
        )

    if not re.fullmatch(
        r"[A-Za-z][A-Za-z .'-]*",
        value
    ):
        return False, (
            f"{field_name} contains invalid characters."
        )

    return True, value


# ============================================================
# EMPLOYEE ID VALIDATION
# ============================================================

def validate_employee_id(employee_id):

    employee_id = clean(employee_id).upper()

    if not employee_id:
        return False, "Employee ID is required."

    if not re.fullmatch(
        r"[A-Z0-9][A-Z0-9._-]{2,29}",
        employee_id
    ):
        return False, (
            "Employee ID must contain 3-30 characters."
        )

    return True, employee_id


# ============================================================
# DATE OF BIRTH VALIDATION
# ============================================================

def validate_dob(dob):

    if not dob:
        return False, "Date of birth is required."

    if dob < date(1950, 1, 1):
        return False, (
            "Date of birth cannot be before 01-Jan-1950."
        )

    if dob > date.today():
        return False, (
            "Date of birth cannot be in the future."
        )

    age = (
        date.today().year
        - dob.year
        - (
            (date.today().month, date.today().day)
            < (dob.month, dob.day)
        )
    )

    if age < 18:
        return False, (
            "Employee must be at least 18 years old."
        )

    return True, dob


# ============================================================
# POSTAL CODE VALIDATION
# ============================================================

def validate_postal_code(value):

    value = clean(value)

    if not value:
        return False, "Postal code is required."

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9 -]{2,11}",
        value
    ):
        return False, "Please enter a valid postal code."

    return True, value


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

def get_env(name):

    value = os.environ.get(name)

    if value is None or not str(value).strip():

        raise RuntimeError(
            f"Missing environment variable: {name}"
        )

    return str(value).strip()


# ============================================================
# PRIVATE KEY
# ============================================================

def get_private_key_bytes():

    configured_key_path = (
        os.environ.get("SNOWFLAKE_PRIVATE_KEY_FILE")
        or os.environ.get("PRIVATE_KEY_FILE")
        or os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH")
        or os.environ.get("PRIVATE_KEY_PATH")
    )
    local_key_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "rsa_key.p8"
    )
    private_key_path = configured_key_path or (
        local_key_path if os.path.isfile(local_key_path) else None
    )

    if private_key_path:
        with open(private_key_path, "r", encoding="utf-8") as f:
            raw_key = f.read().strip()
    else:
        raw_key = get_env("SNOWFLAKE_PRIVATE_KEY")

    raw_key = raw_key.replace("\\n", "\n").strip()

    passphrase = os.environ.get(
        "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
        ""
    )

    passphrase = passphrase.replace(
        "\\n",
        "\n"
    )

    try:

        if (
            "-----BEGIN PRIVATE KEY-----"
            in raw_key
            or
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            in raw_key
        ):

            private_key = serialization.load_pem_private_key(
                raw_key.encode("utf-8"),
                password=(
                    passphrase.encode("utf-8")
                    if passphrase
                    else None
                )
            )

        else:

            der_key = base64.b64decode(
                raw_key
            )

            private_key = serialization.load_der_private_key(
                der_key,
                password=(
                    passphrase.encode("utf-8")
                    if passphrase
                    else None
                )
            )

        return private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    except Exception as exc:

        raise RuntimeError(
            "Could not load the Snowflake private key. "
            "Make sure SNOWFLAKE_PRIVATE_KEY or SNOWFLAKE_PRIVATE_KEY_FILE contains "
            "the PRIVATE KEY, not the PUBLIC KEY."
        ) from exc


# ============================================================
# SNOWFLAKE CONNECTION
# ============================================================

@st.cache_resource
def get_connection():

    private_key = get_private_key_bytes()

    conn = snowflake.connector.connect(

        account=get_env(
            "SNOWFLAKE_ACCOUNT"
        ),

        user=get_env(
            "SNOWFLAKE_USER"
        ),

        authenticator="SNOWFLAKE_JWT",

        private_key=private_key,

        warehouse=get_env(
            "SNOWFLAKE_WAREHOUSE"
        ),

        role=get_env(
            "SNOWFLAKE_ROLE"
        ),

        database=DATABASE,

        schema=SCHEMA,

        autocommit=True
    )

    return conn


# ============================================================
# EXECUTE SQL
# ============================================================

def execute_query(
    sql,
    params=None,
    fetch=True
):

    for attempt in range(2):
        conn = get_connection()
        cursor = None

        try:
            cursor = conn.cursor()
            cursor.execute(sql, params or ())

            if fetch:
                rows = cursor.fetchall()

                if cursor.description:
                    columns = [
                        column[0]
                        for column in cursor.description
                    ]

                    return pd.DataFrame(
                        rows,
                        columns=columns
                    )

                return pd.DataFrame()

            return None

        except Exception as exc:
            error_text = str(exc).lower()
            token_expired = (
                "390114" in error_text
                or "authentication token has expired" in error_text
            )

            if attempt == 0 and token_expired:
                try:
                    conn.close()
                finally:
                    get_connection.clear()
                continue

            raise

        finally:
            if cursor is not None:
                cursor.close()


@st.cache_resource
def ensure_feature_tables():

    execute_query(
        f"""
        CREATE TABLE IF NOT EXISTS {EDIT_REQUESTS_TABLE} (
            EMPLOYEE_ID VARCHAR,
            REASON VARCHAR,
            STATUS VARCHAR DEFAULT 'PENDING',
            REQUESTED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        fetch=False
    )
    execute_query(
        f"""
        CREATE TABLE IF NOT EXISTS {POLICY_ACK_TABLE} (
            EMPLOYEE_ID VARCHAR,
            POLICY_KEY VARCHAR,
            POLICY_VERSION VARCHAR,
            ACKNOWLEDGED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        fetch=False
    )
    execute_query(
        f"""
        CREATE TABLE IF NOT EXISTS {MESSAGES_TABLE} (
            MESSAGE_ID NUMBER AUTOINCREMENT,
            EMPLOYEE_ID VARCHAR,
            TITLE VARCHAR,
            MESSAGE VARCHAR,
            CREATED_BY VARCHAR,
            CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        fetch=False
    )
    execute_query(
        f"""
        CREATE TABLE IF NOT EXISTS {SUPPORT_TABLE} (
            REQUEST_ID NUMBER AUTOINCREMENT,
            EMPLOYEE_ID VARCHAR,
            SUBJECT VARCHAR,
            DESCRIPTION VARCHAR,
            STATUS VARCHAR DEFAULT 'OPEN',
            CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
            UPDATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
        )
        """,
        fetch=False
    )


def get_policy_acknowledgments(employee_id):

    ensure_feature_tables()
    df = execute_query(
        f"""
        SELECT POLICY_KEY
        FROM {POLICY_ACK_TABLE}
        WHERE EMPLOYEE_ID = %s
        """,
        (employee_id,)
    )
    return set(df["POLICY_KEY"].tolist()) if not df.empty else set()


def acknowledge_policies(employee_id):

    ensure_feature_tables()
    acknowledged = get_policy_acknowledgments(employee_id)
    for policy_key, _, policy_version in POLICIES:
        if policy_key in acknowledged:
            continue
        execute_query(
            f"""
            INSERT INTO {POLICY_ACK_TABLE}
                (EMPLOYEE_ID, POLICY_KEY, POLICY_VERSION)
            VALUES (%s, %s, %s)
            """,
            (employee_id, policy_key, policy_version),
            fetch=False
        )


def get_employee_messages(employee_id):

    ensure_feature_tables()
    return execute_query(
        f"""
        SELECT TITLE, MESSAGE, CREATED_AT
        FROM {MESSAGES_TABLE}
        WHERE EMPLOYEE_ID = %s
        ORDER BY CREATED_AT DESC
        """,
        (employee_id,)
    )


def send_employee_message(employee_id, title, message):

    ensure_feature_tables()
    execute_query(
        f"""
        INSERT INTO {MESSAGES_TABLE}
            (EMPLOYEE_ID, TITLE, MESSAGE, CREATED_BY)
        VALUES (%s, %s, %s, %s)
        """,
        (employee_id, title, message, "HR"),
        fetch=False
    )


def get_support_requests(employee_id=None):

    ensure_feature_tables()
    if employee_id:
        return execute_query(
            f"""
            SELECT * FROM {SUPPORT_TABLE}
            WHERE EMPLOYEE_ID = %s
            ORDER BY CREATED_AT DESC
            """,
            (employee_id,)
        )
    return execute_query(
        f"SELECT * FROM {SUPPORT_TABLE} ORDER BY CREATED_AT DESC"
    )


def create_support_request(employee_id, subject, description):

    ensure_feature_tables()
    execute_query(
        f"""
        INSERT INTO {SUPPORT_TABLE}
            (EMPLOYEE_ID, SUBJECT, DESCRIPTION)
        VALUES (%s, %s, %s)
        """,
        (employee_id, subject, description),
        fetch=False
    )


def update_support_request(request_id, status):

    ensure_feature_tables()
    execute_query(
        f"""
        UPDATE {SUPPORT_TABLE}
        SET STATUS = %s, UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE REQUEST_ID = %s
        """,
        (status, request_id),
        fetch=False
    )


# ============================================================
# GET EMPLOYEE
# ============================================================

def get_employee(employee_id):

    sql = f"""
        SELECT *
        FROM {FULL_TABLE}
        WHERE UPPER(EMPLOYEE_ID) = UPPER(%s)
        LIMIT 1
    """

    df = execute_query(
        sql,
        (employee_id,)
    )

    if df.empty:
        return None

    return df.iloc[0].to_dict()


# ============================================================
# CHECK EMPLOYEE ID
# ============================================================

def employee_id_exists(employee_id):

    sql = f"""
        SELECT COUNT(*)
        FROM {FULL_TABLE}
        WHERE UPPER(EMPLOYEE_ID) = UPPER(%s)
    """

    df = execute_query(
        sql,
        (employee_id,)
    )

    return int(df.iloc[0, 0]) > 0


def get_next_employee_id():

    sql = f"""
        SELECT COALESCE(
            MAX(TRY_TO_NUMBER(REGEXP_SUBSTR(EMPLOYEE_ID, '[0-9]+$'))),
            0
        ) AS MAX_EMPLOYEE_NUMBER
        FROM {FULL_TABLE}
    """

    df = execute_query(sql)
    next_number = int(df.iloc[0, 0] or 0) + 1

    return f"EMP{next_number:03d}"


# ============================================================
# EMPLOYEE LOGIN
# ============================================================

def authenticate_employee(
    work_email,
    password
):

    sql = f"""
        SELECT *
        FROM {FULL_TABLE}
        WHERE LOWER(WORK_EMAIL) = LOWER(%s)
        LIMIT 1
    """

    df = execute_query(
        sql,
        (
            work_email
        )
    )

    if df.empty or not verify_password(
        password,
        df.iloc[0].to_dict().get("EMPLOYEE_PASSWORD_HASH")
    ):
        return None

    return df.iloc[0].to_dict()


def request_employee_edit(employee_id, reason):

    ensure_feature_tables()

    execute_query(
        f"DELETE FROM {EDIT_REQUESTS_TABLE} WHERE EMPLOYEE_ID = %s",
        (employee_id,),
        fetch=False
    )
    execute_query(
        f"""
        INSERT INTO {EDIT_REQUESTS_TABLE} (EMPLOYEE_ID, REASON)
        VALUES (%s, %s)
        """,
        (employee_id, reason),
        fetch=False
    )

    sql = f"""
        UPDATE {FULL_TABLE}
        SET EDIT_REQUESTED = TRUE,
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE EMPLOYEE_ID = %s
    """

    execute_query(
        sql,
        (employee_id,),
        fetch=False
    )


def grant_employee_edit_access(employee_id):

    sql = f"""
        UPDATE {FULL_TABLE}
        SET EDIT_ALLOWED = TRUE,
            EDIT_REQUESTED = FALSE,
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE EMPLOYEE_ID = %s
    """

    execute_query(
        sql,
        (employee_id,),
        fetch=False
    )


def get_edit_request_reason(employee_id):

    ensure_feature_tables()
    df = execute_query(
        f"""
        SELECT REASON, REQUESTED_AT
        FROM {EDIT_REQUESTS_TABLE}
        WHERE EMPLOYEE_ID = %s
        ORDER BY REQUESTED_AT DESC
        LIMIT 1
        """,
        (employee_id,)
    )
    return None if df.empty else df.iloc[0].to_dict()


# ============================================================
# EMAIL DUPLICATE CHECK
# ============================================================

def email_exists(
    email,
    column,
    exclude_employee_id=None
):

    allowed_columns = {
        "WORK_EMAIL",
        "PERSONAL_EMAIL"
    }

    if column not in allowed_columns:

        raise ValueError(
            "Invalid email column."
        )

    if exclude_employee_id:

        sql = f"""
            SELECT COUNT(*)
            FROM {FULL_TABLE}
            WHERE LOWER({column}) = LOWER(%s)
            AND EMPLOYEE_ID <> %s
        """

        df = execute_query(
            sql,
            (
                email,
                exclude_employee_id
            )
        )

    else:

        sql = f"""
            SELECT COUNT(*)
            FROM {FULL_TABLE}
            WHERE LOWER({column}) = LOWER(%s)
        """

        df = execute_query(
            sql,
            (email,)
        )

    return int(df.iloc[0, 0]) > 0


# ============================================================
# PHONE DUPLICATE CHECK
# ============================================================

def phone_exists(
    phone,
    exclude_employee_id=None
):

    if exclude_employee_id:

        sql = f"""
            SELECT COUNT(*)
            FROM {FULL_TABLE}
            WHERE PHONE = %s
            AND EMPLOYEE_ID <> %s
        """

        df = execute_query(
            sql,
            (
                phone,
                exclude_employee_id
            )
        )

    else:

        sql = f"""
            SELECT COUNT(*)
            FROM {FULL_TABLE}
            WHERE PHONE = %s
        """

        df = execute_query(
            sql,
            (phone,)
        )

    return int(df.iloc[0, 0]) > 0


# ============================================================
# REQUIRED EMPLOYEE FIELDS
# ============================================================

REQUIRED_EMPLOYEE_FIELDS = [

    "FIRST_NAME",
    "LAST_NAME",
    "DATE_OF_BIRTH",
    "GENDER",
    "PERSONAL_EMAIL",
    "PHONE",
    "ADDRESS_LINE",
    "CITY",
    "STATE",
    "COUNTRY",
    "POSTAL_CODE",
    "WORK_EMAIL",
    "DEPARTMENT",
    "DESIGNATION",
    "JOINING_DATE",
    "REPORTING_MANAGER",
    "WORK_LOCATION",
    "WORK_MODE",
    "EMERGENCY_CONTACT_NAME",
    "EMERGENCY_CONTACT_RELATION",
    "EMERGENCY_CONTACT_PHONE",
    "BLOOD_GROUP"

]


# ============================================================
# CHECK ONBOARDING COMPLETION
# ============================================================

def onboarding_complete(employee):

    for field in REQUIRED_EMPLOYEE_FIELDS:

        value = employee.get(field)

        if value is None:
            return False

        if str(value).strip() == "":
            return False

    return True


def employee_profile_metrics(employee):

    tracked_fields = [
        "FIRST_NAME",
        "LAST_NAME",
        "DATE_OF_BIRTH",
        "GENDER",
        "PERSONAL_EMAIL",
        "PHONE",
        "ADDRESS_LINE",
        "CITY",
        "STATE",
        "COUNTRY",
        "POSTAL_CODE",
        "WORK_EMAIL",
        "DEPARTMENT",
        "DESIGNATION",
        "SALARY",
        "JOINING_DATE",
        "REPORTING_MANAGER",
        "WORK_LOCATION",
        "WORK_MODE",
        "EMERGENCY_CONTACT_NAME",
        "EMERGENCY_CONTACT_RELATION",
        "EMERGENCY_CONTACT_PHONE",
        "BLOOD_GROUP"
    ]

    completed_fields = sum(
        1
        for field in tracked_fields
        if employee.get(field) is not None
        and clean(employee.get(field))
    )
    completion = round(100 * completed_fields / len(tracked_fields))
    missing_fields = len(tracked_fields) - completed_fields

    if missing_fields == 0:
        status = "Completed"
    elif completed_fields == 0:
        status = "Not Started"
    else:
        status = "In Progress"

    if employee.get("EDIT_REQUESTED"):
        risk = "Medium"
    elif missing_fields >= 5:
        risk = "High"
    elif missing_fields > 0:
        risk = "Medium"
    else:
        risk = "Low"

    return completion, status, risk


def hr_command_center():

    st.header("Onboarding Command Center")

    try:
        df = execute_query(
            f"SELECT * FROM {FULL_TABLE} ORDER BY EMPLOYEE_ID"
        )
    except Exception as exc:
        st.error(f"Unable to load onboarding metrics: {exc}")
        return

    if df.empty:
        st.info("No employee records found.")
        return

    records = df.to_dict("records")
    metrics = [employee_profile_metrics(record) for record in records]
    df["COMPLETION"] = [metric[0] for metric in metrics]
    df["ONBOARDING_STATUS"] = [metric[1] for metric in metrics]
    df["RISK"] = [metric[2] for metric in metrics]

    total, completed, pending, high_risk = st.columns(4)
    total.metric("Total Employees", len(df))
    completed.metric(
        "Completed",
        int((df["ONBOARDING_STATUS"] == "Completed").sum())
    )
    pending.metric(
        "Pending",
        int((df["ONBOARDING_STATUS"] != "Completed").sum())
    )
    high_risk.metric(
        "High Risk",
        int((df["RISK"] == "High").sum())
    )

    search = st.text_input(
        "Search employees",
        placeholder="Employee ID, name, email, or department",
        key="command_center_search"
    ).strip().lower()
    status_filter = st.selectbox(
        "Status",
        ["All", "Not Started", "In Progress", "Completed"],
        key="command_center_status"
    )

    display_df = df.copy()
    if search:
        search_columns = [
            "EMPLOYEE_ID",
            "FIRST_NAME",
            "LAST_NAME",
            "WORK_EMAIL",
            "DEPARTMENT"
        ]
        matches = display_df[search_columns].fillna("").astype(str).apply(
            lambda column: column.str.lower().str.contains(search)
        ).any(axis=1)
        display_df = display_df[matches]

    if status_filter != "All":
        display_df = display_df[
            display_df["ONBOARDING_STATUS"] == status_filter
        ]

    display_columns = [
        "EMPLOYEE_ID",
        "FIRST_NAME",
        "LAST_NAME",
        "DEPARTMENT",
        "COMPLETION",
        "ONBOARDING_STATUS",
        "RISK",
        "EDIT_REQUESTED"
    ]
    st.dataframe(
        display_df[display_columns],
        width="stretch",
        hide_index=True,
        column_config={
            "COMPLETION": st.column_config.ProgressColumn(
                "Completion",
                min_value=0,
                max_value=100,
                format="%d%%"
            )
        }
    )


# ============================================================
# HR LOGIN
# ============================================================

def hr_login_page():

    st.subheader("HR Login")

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter HR password"
    )

    if st.button("Login", type="primary"):

        if HR_PASSWORD and secrets.compare_digest(password, HR_PASSWORD):
            st.session_state["hr_logged_in"] = True
            mark_activity()
            st.success("HR login successful.")
            st.rerun()

        else:
            st.error("Invalid HR password.")


# ============================================================
# HR CREATE EMPLOYEE
# ============================================================

def hr_create_employee():

    st.header(
        "Create Employee"
    )

    st.info(
        "All employee information is required before the record can be created."
    )

    try:
        next_employee_id = get_next_employee_id()
    except Exception as exc:
        st.error(f"Unable to determine the next employee ID: {exc}")
        return

    with st.form(
        "hr_create_employee"
    ):

        col1, col2 = st.columns(2)

        with col1:

            employee_id = st.text_input(
                "Employee ID *",
                value=next_employee_id,
                disabled=True,
                key="create_employee_id",
                help="Generated from the highest employee ID in Snowflake."
            )

            first_name = st.text_input("First Name *", key="create_first_name")
            last_name = st.text_input("Last Name *", key="create_last_name")
            date_of_birth = st.date_input(
                "Date of Birth *",
                value=date(2000, 1, 1),
                min_value=date(1950, 1, 1),
                max_value=date.today(),
                key="create_date_of_birth"
            )
            gender = st.selectbox(
                "Gender *",
                ["Male", "Female", "Other", "Prefer not to say"],
                key="create_gender"
            )

            work_email = st.text_input(
                "Work Email *",
                placeholder="employee@company.com",
                key="create_work_email"
            )

            personal_email = st.text_input(
                "Personal Email *",
                placeholder="personal@example.com",
                key="create_personal_email"
            )

            phone = st.text_input(
                "Phone Number *",
                placeholder="+919876543210",
                key="create_phone"
            )

            address_line = st.text_area("Address *", key="create_address")
            city = st.text_input("City *", key="create_city")
            state = st.text_input("State *", key="create_state")
            country = st.text_input("Country *", key="create_country")
            postal_code = st.text_input("Postal Code *", key="create_postal_code")

            department = st.text_input(
                "Department *",
                key="create_department"
            )

            designation = st.text_input(
                "Designation *",
                key="create_designation"
            )

            salary = st.number_input(
                "Salary *",
                min_value=0.01,
                step=1000.0,
                format="%.2f",
                key="create_salary"
            )

            employee_password = st.text_input(
                "Employee Password *",
                type="password",
                key="create_employee_password",
                help="Give this password to the employee securely."
            )

        with col2:

            joining_date = st.date_input(
                "Joining Date *",
                value=date.today(),
                key="create_joining_date"
            )

            reporting_manager = st.text_input(
                "Reporting Manager *",
                key="create_reporting_manager"
            )

            work_location = st.selectbox(
                "Work Location *",
                [
                    "Chennai",
                    "Bangalore",
                    "Hyderabad",
                    "Mumbai",
                    "Delhi",
                    "Pune",
                    "Remote",
                    "Other"
                ],
                key="create_work_location"
            )

            work_mode = st.selectbox(
                "Work Mode *",
                [
                    "Office",
                    "Hybrid",
                    "Remote"
                ],
                key="create_work_mode"
            )

            emergency_name = st.text_input(
                "Emergency Contact Name *",
                key="create_emergency_name"
            )
            emergency_relation = st.selectbox(
                "Emergency Contact Relation *",
                ["Parent", "Spouse", "Sibling", "Child", "Relative", "Friend", "Other"],
                key="create_emergency_relation"
            )
            emergency_phone = st.text_input(
                "Emergency Contact Phone *",
                placeholder="+919876543210",
                key="create_emergency_phone"
            )
            blood_group = st.selectbox(
                "Blood Group *",
                ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
                key="create_blood_group"
            )

        submit = st.form_submit_button(
            "Create Employee",
            type="primary",
            width="stretch"
        )

    if not submit:
        return

    errors = []

    valid, employee_id_result = validate_employee_id(
        employee_id
    )

    if not valid:
        errors.append(
            employee_id_result
        )
    else:
        employee_id = employee_id_result

    valid, work_email_result = validate_email_address(
        work_email
    )

    if not valid:
        errors.append(
            f"Work Email: {work_email_result}"
        )
    else:
        work_email = work_email_result

    for value, label in [
        (first_name, "First Name"),
        (last_name, "Last Name")
    ]:
        valid, result = validate_name(value, label)
        if not valid:
            errors.append(result)
        elif label == "First Name":
            first_name = result
        else:
            last_name = result

    valid, result = validate_dob(date_of_birth)
    if not valid:
        errors.append(result)

    valid, personal_email_result = validate_email_address(personal_email)
    if not valid:
        errors.append(f"Personal Email: {personal_email_result}")
    else:
        personal_email = personal_email_result

    valid, phone_result = validate_phone_number(phone)
    if not valid:
        errors.append(f"Phone: {phone_result}")
    else:
        phone = phone_result

    valid, emergency_phone_result = validate_phone_number(emergency_phone)
    if not valid:
        errors.append(f"Emergency Contact Phone: {emergency_phone_result}")
    else:
        emergency_phone = emergency_phone_result

    valid, postal_result = validate_postal_code(postal_code)
    if not valid:
        errors.append(postal_result)
    else:
        postal_code = postal_result

    for value, label in [

        (address_line, "Address"),
        (city, "City"),
        (state, "State"),
        (country, "Country"),
        (emergency_name, "Emergency Contact Name"),
        (department, "Department"),
        (designation, "Designation"),
        (reporting_manager, "Reporting Manager")

    ]:

        valid, result = required(
            value,
            label
        )

        if not valid:
            errors.append(result)

    valid, password_result = validate_employee_password(
        employee_password
    )

    if not valid:
        errors.append(password_result)
    else:
        employee_password_hash = hash_password(password_result)

    if errors:

        st.error(
            "Please correct the following:"
        )

        for error in errors:
            st.error(error)

        return

    try:

        if employee_id_exists(
            employee_id
        ):

            st.warning(
                f"Employee ID '{employee_id}' "
                "already exists."
            )

            return

        if email_exists(
            work_email,
            "WORK_EMAIL"
        ):

            st.warning(
                "This work email is already "
                "assigned to another employee."
            )

            return

        if email_exists(personal_email, "PERSONAL_EMAIL"):
            st.warning("This personal email is already assigned to another employee.")
            return

        if phone_exists(phone):
            st.warning("This phone number is already assigned to another employee.")
            return

        if phone_exists(emergency_phone):
            st.warning("This emergency contact phone is already assigned to another employee.")
            return

        sql = f"""
            INSERT INTO {FULL_TABLE}
            (
                EMPLOYEE_ID,
                FIRST_NAME,
                LAST_NAME,
                DATE_OF_BIRTH,
                GENDER,
                WORK_EMAIL,
                PERSONAL_EMAIL,
                PHONE,
                ADDRESS_LINE,
                CITY,
                STATE,
                COUNTRY,
                POSTAL_CODE,
                DEPARTMENT,
                DESIGNATION,
                SALARY,
                EMPLOYEE_PASSWORD_HASH,
                EDIT_ALLOWED,
                EDIT_REQUESTED,
                JOINING_DATE,
                REPORTING_MANAGER,
                WORK_LOCATION,
                WORK_MODE,
                EMERGENCY_CONTACT_NAME,
                EMERGENCY_CONTACT_RELATION,
                EMERGENCY_CONTACT_PHONE,
                BLOOD_GROUP,
                UPDATED_AT
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                FALSE,
                FALSE,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                CURRENT_TIMESTAMP()
            )
        """

        execute_query(
            sql,
            (
                employee_id,
                first_name,
                last_name,
                date_of_birth,
                gender,
                work_email,
                personal_email,
                phone,
                address_line,
                city,
                state,
                country,
                postal_code,
                department,
                designation,
                salary,
                employee_password_hash,
                joining_date,
                reporting_manager,
                work_location,
                work_mode,
                emergency_name,
                emergency_relation,
                emergency_phone,
                blood_group
            ),
            fetch=False
        )

        st.success(
            f"Employee {employee_id} created successfully."
        )

        st.info(
            "Employee can now use the Employee Portal "
            "with their Employee ID and Work Email."
        )

    except Exception as exc:

        st.error(
            f"Unable to create employee: {exc}"
        )


# ============================================================
# HR VIEW EMPLOYEES
# ============================================================

def hr_view_employees():

    st.header(
        "Employee Records"
    )

    try:

        sql = f"""
            SELECT *
            FROM {FULL_TABLE}
            ORDER BY EMPLOYEE_ID
        """

        df = execute_query(
            sql
        )

        if df.empty:

            st.info(
                "No employee records found."
            )

            return

        st.dataframe(
            df,
            width="stretch",
            hide_index=True
        )

        pending_employee_ids = [
            row["EMPLOYEE_ID"]
            for _, row in df.iterrows()
            if str(row.get("EDIT_REQUESTED")).strip().upper()
            in {"TRUE", "1", "Y"}
        ]

        if pending_employee_ids:
            st.subheader("Pending Edit Requests")
            selected_pending_id = st.selectbox(
                "Employee requesting edit access",
                pending_employee_ids,
                key="pending_edit_employee"
            )

            if st.button(
                "Grant Edit Access",
                type="primary",
                key="grant_edit_access_records"
            ):
                try:
                    grant_employee_edit_access(selected_pending_id)
                    st.success("Edit access granted successfully.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Unable to grant edit access: {exc}")
        else:
            st.info("No pending employee edit requests.")

    except Exception as exc:

        st.error(
            f"Unable to load employees: {exc}"
        )


# ============================================================
# HR EDIT EMPLOYEE
# ============================================================

def hr_edit_employee():

    st.header(
        "Edit Employee"
    )

    try:

        sql = f"""
            SELECT EMPLOYEE_ID
            FROM {FULL_TABLE}
            ORDER BY EMPLOYEE_ID
        """

        df = execute_query(
            sql
        )

        if df.empty:

            st.info(
                "No employee records available."
            )

            return

        employee_ids = df[
            "EMPLOYEE_ID"
        ].tolist()

        selected_id = st.selectbox(
            "Select Employee",
            employee_ids
        )

        employee = get_employee(
            selected_id
        )

        if employee is None:

            st.error(
                "Employee record not found."
            )

            return

        if employee.get("EDIT_REQUESTED"):
            st.warning(
                "This employee has requested permission to edit their details."
            )
            request_details = get_edit_request_reason(selected_id)
            if request_details:
                st.caption(
                    f"Reason: {clean(request_details.get('REASON'))} "
                    f"({clean(request_details.get('REQUESTED_AT'))})"
                )

            if st.button(
                "Grant Edit Access",
                type="primary",
                key=f"grant_edit_access_{selected_id}"
            ):
                try:
                    grant_employee_edit_access(selected_id)
                    st.success("Edit access granted successfully.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Unable to grant edit access: {exc}")

        st.divider()

        with st.form(
            "hr_edit_form"
        ):

            st.subheader(
                "Employee Information"
            )

            c1, c2 = st.columns(2)

            with c1:

                first_name = st.text_input(
                    "First Name *",
                    value=clean(
                        employee.get(
                            "FIRST_NAME"
                        )
                    )
                )

                last_name = st.text_input(
                    "Last Name *",
                    value=clean(
                        employee.get(
                            "LAST_NAME"
                        )
                    )
                )

                dob = employee.get(
                    "DATE_OF_BIRTH"
                )

                date_of_birth = st.date_input(
                    "Date of Birth *",
                    value=(
                        dob
                        if dob
                        else date(2000, 1, 1)
                    ),
                    min_value=date(1950, 1, 1),
                    max_value=date.today()
                )

                gender_options = [
                    "Male",
                    "Female",
                    "Other",
                    "Prefer not to say"
                ]

                current_gender = clean(
                    employee.get(
                        "GENDER"
                    )
                )

                gender = st.selectbox(
                    "Gender *",
                    gender_options,
                    index=(
                        gender_options.index(
                            current_gender
                        )
                        if current_gender
                        in gender_options
                        else 0
                    )
                )

                personal_email = st.text_input(
                    "Personal Email *",
                    value=clean(
                        employee.get(
                            "PERSONAL_EMAIL"
                        )
                    )
                )

                phone = st.text_input(
                    "Phone *",
                    value=clean(
                        employee.get(
                            "PHONE"
                        )
                    )
                )

            with c2:

                address_line = st.text_area(
                    "Address *",
                    value=clean(
                        employee.get(
                            "ADDRESS_LINE"
                        )
                    )
                )

                city = st.text_input(
                    "City *",
                    value=clean(
                        employee.get(
                            "CITY"
                        )
                    )
                )

                state = st.text_input(
                    "State *",
                    value=clean(
                        employee.get(
                            "STATE"
                        )
                    )
                )

                country = st.text_input(
                    "Country *",
                    value=clean(
                        employee.get(
                            "COUNTRY"
                        )
                    )
                )

                postal_code = st.text_input(
                    "Postal Code *",
                    value=clean(
                        employee.get(
                            "POSTAL_CODE"
                        )
                    )
                )

            st.subheader(
                "HR Controlled Information"
            )

            h1, h2 = st.columns(2)

            with h1:

                work_email = st.text_input(
                    "Work Email *",
                    value=clean(
                        employee.get(
                            "WORK_EMAIL"
                        )
                    )
                )

                department = st.text_input(
                    "Department *",
                    value=clean(
                        employee.get(
                            "DEPARTMENT"
                        )
                    )
                )

                designation = st.text_input(
                    "Designation *",
                    value=clean(
                        employee.get(
                            "DESIGNATION"
                        )
                    )
                )

                salary = st.number_input(
                    "Salary *",
                    min_value=0.01,
                    value=float(employee.get("SALARY") or 0.01),
                    step=1000.0,
                    format="%.2f"
                )

                new_employee_password = st.text_input(
                    "New Employee Password",
                    type="password",
                    help="Leave blank to keep the current password."
                )

                allow_employee_edit = st.checkbox(
                    "Allow employee to edit submitted details",
                    value=bool(employee.get("EDIT_ALLOWED")),
                    help="Employees can edit only while this permission is enabled."
                )

                reporting_manager = st.text_input(
                    "Reporting Manager *",
                    value=clean(
                        employee.get(
                            "REPORTING_MANAGER"
                        )
                    )
                )

            with h2:

                joining_date = st.date_input(
                    "Joining Date *",
                    value=(
                        employee.get(
                            "JOINING_DATE"
                        )
                        if employee.get(
                            "JOINING_DATE"
                        )
                        else date.today()
                    )
                )

                location_options = [
                    "Chennai",
                    "Bangalore",
                    "Hyderabad",
                    "Mumbai",
                    "Delhi",
                    "Pune",
                    "Remote",
                    "Other"
                ]

                current_location = clean(
                    employee.get(
                        "WORK_LOCATION"
                    )
                )

                work_location = st.selectbox(
                    "Work Location *",
                    location_options,
                    index=(
                        location_options.index(
                            current_location
                        )
                        if current_location
                        in location_options
                        else 0
                    )
                )

                mode_options = [
                    "Office",
                    "Hybrid",
                    "Remote"
                ]

                current_mode = clean(
                    employee.get(
                        "WORK_MODE"
                    )
                )

                work_mode = st.selectbox(
                    "Work Mode *",
                    mode_options,
                    index=(
                        mode_options.index(
                            current_mode
                        )
                        if current_mode
                        in mode_options
                        else 0
                    )
                )

            st.subheader(
                "Emergency Contact"
            )

            e1, e2 = st.columns(2)

            with e1:

                emergency_name = st.text_input(
                    "Emergency Contact Name *",
                    value=clean(
                        employee.get(
                            "EMERGENCY_CONTACT_NAME"
                        )
                    )
                )

                relation_options = [
                    "Parent",
                    "Spouse",
                    "Sibling",
                    "Child",
                    "Relative",
                    "Friend",
                    "Other"
                ]

                current_relation = clean(
                    employee.get(
                        "EMERGENCY_CONTACT_RELATION"
                    )
                )

                emergency_relation = st.selectbox(
                    "Emergency Contact Relation *",
                    relation_options,
                    index=(
                        relation_options.index(
                            current_relation
                        )
                        if current_relation
                        in relation_options
                        else 0
                    )
                )

            with e2:

                emergency_phone = st.text_input(
                    "Emergency Contact Phone *",
                    value=clean(
                        employee.get(
                            "EMERGENCY_CONTACT_PHONE"
                        )
                    )
                )

                blood_options = [
                    "A+",
                    "A-",
                    "B+",
                    "B-",
                    "AB+",
                    "AB-",
                    "O+",
                    "O-"
                ]

                current_blood = clean(
                    employee.get(
                        "BLOOD_GROUP"
                    )
                )

                blood_group = st.selectbox(
                    "Blood Group *",
                    blood_options,
                    index=(
                        blood_options.index(
                            current_blood
                        )
                        if current_blood
                        in blood_options
                        else 0
                    )
                )

            save = st.form_submit_button(
                "Save Changes",
                type="primary",
                width="stretch"
            )

        if not save:
            return

        errors = []

        validations = [

            validate_name(
                first_name,
                "First Name"
            ),

            validate_name(
                last_name,
                "Last Name"
            ),

            validate_dob(
                date_of_birth
            ),

            validate_email_address(
                personal_email
            ),

            validate_email_address(
                work_email
            ),

            validate_phone_number(
                phone
            ),

            validate_phone_number(
                emergency_phone
            ),

            validate_postal_code(
                postal_code
            )

        ]

        for valid, result in validations:

            if not valid:
                errors.append(result)

        for value, field_name in [

            (address_line, "Address"),
            (city, "City"),
            (state, "State"),
            (country, "Country"),
            (department, "Department"),
            (designation, "Designation"),
            (reporting_manager, "Reporting Manager"),
            (emergency_name, "Emergency Contact Name")

        ]:

            valid, result = required(
                value,
                field_name
            )

            if not valid:
                errors.append(result)

        if salary <= 0:
            errors.append("Salary must be greater than zero.")

        employee_password_hash = employee.get(
            "EMPLOYEE_PASSWORD_HASH"
        )

        if new_employee_password:
            valid, password_result = validate_employee_password(
                new_employee_password
            )

            if not valid:
                errors.append(password_result)
            else:
                employee_password_hash = hash_password(password_result)

        if errors:

            st.error(
                "Please correct the following:"
            )

            for error in errors:
                st.error(error)

            return

        # Normalize values
        _, personal_email = validate_email_address(
            personal_email
        )

        _, work_email = validate_email_address(
            work_email
        )

        _, phone = validate_phone_number(
            phone
        )

        _, emergency_phone = validate_phone_number(
            emergency_phone
        )

        try:

            if email_exists(
                work_email,
                "WORK_EMAIL",
                selected_id
            ):

                st.warning(
                    "This work email belongs "
                    "to another employee."
                )

                return

            if email_exists(
                personal_email,
                "PERSONAL_EMAIL",
                selected_id
            ):

                st.warning(
                    "This personal email belongs "
                    "to another employee."
                )

                return

            if phone_exists(
                phone,
                selected_id
            ):

                st.warning(
                    "This phone number belongs "
                    "to another employee."
                )

                return

            sql = f"""
                UPDATE {FULL_TABLE}
                SET

                    FIRST_NAME = %s,
                    LAST_NAME = %s,
                    DATE_OF_BIRTH = %s,
                    GENDER = %s,
                    PERSONAL_EMAIL = %s,
                    PHONE = %s,
                    ADDRESS_LINE = %s,
                    CITY = %s,
                    STATE = %s,
                    COUNTRY = %s,
                    POSTAL_CODE = %s,

                    WORK_EMAIL = %s,
                    DEPARTMENT = %s,
                    DESIGNATION = %s,
                    SALARY = %s,
                    EMPLOYEE_PASSWORD_HASH = %s,
                    EDIT_ALLOWED = %s,
                    EDIT_REQUESTED = %s,
                    JOINING_DATE = %s,
                    REPORTING_MANAGER = %s,
                    WORK_LOCATION = %s,
                    WORK_MODE = %s,

                    EMERGENCY_CONTACT_NAME = %s,
                    EMERGENCY_CONTACT_RELATION = %s,
                    EMERGENCY_CONTACT_PHONE = %s,
                    BLOOD_GROUP = %s,

                    UPDATED_AT = CURRENT_TIMESTAMP()

                WHERE EMPLOYEE_ID = %s
            """

            execute_query(
                sql,
                (
                    first_name,
                    last_name,
                    date_of_birth,
                    gender,
                    personal_email,
                    phone,
                    address_line,
                    city,
                    state,
                    country,
                    postal_code,
                    work_email,
                    department,
                    designation,
                    salary,
                    employee_password_hash,
                    allow_employee_edit,
                    False if allow_employee_edit else bool(
                        employee.get("EDIT_REQUESTED")
                    ),
                    joining_date,
                    reporting_manager,
                    work_location,
                    work_mode,
                    emergency_name,
                    emergency_relation,
                    emergency_phone,
                    blood_group,
                    selected_id
                ),
                fetch=False
            )

            st.success(
                "Employee information updated successfully."
            )

        except Exception as exc:

            st.error(
                f"Unable to update employee: {exc}"
            )

    except Exception as exc:

        st.error(
            f"Unable to open employee editor: {exc}"
        )


# ============================================================
# HR COMMUNICATION CENTER
# ============================================================

def hr_communication_center():

    st.header("HR Communication Center")

    try:
        employee_df = execute_query(
            f"""
            SELECT EMPLOYEE_ID, FIRST_NAME, LAST_NAME, WORK_EMAIL
            FROM {FULL_TABLE}
            ORDER BY EMPLOYEE_ID
            """
        )
        if employee_df.empty:
            st.info("No employees available.")
            return

        employee_options = employee_df["EMPLOYEE_ID"].tolist()
        selected_id = st.selectbox(
            "Employee",
            employee_options,
            key="message_employee_id"
        )

        with st.form("hr_message_form"):
            title = st.text_input("Message title *")
            message = st.text_area("Message *")
            send = st.form_submit_button(
                "Send Message",
                type="primary",
                width="stretch"
            )

        if send:
            if not title.strip() or not message.strip():
                st.error("Message title and message are required.")
            else:
                send_employee_message(
                    selected_id,
                    title.strip(),
                    message.strip()
                )
                st.success("Message sent successfully.")
                st.rerun()

        st.subheader("Support Requests")
        support_df = get_support_requests()
        if support_df.empty:
            st.info("No support requests found.")
            return

        st.dataframe(
            support_df,
            hide_index=True,
            width="stretch"
        )
        request_ids = support_df["REQUEST_ID"].tolist()
        selected_request = st.selectbox(
            "Support request",
            request_ids,
            key="hr_support_request_id"
        )
        new_status = st.selectbox(
            "Update status",
            ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"],
            key="hr_support_status"
        )
        if st.button(
            "Update Support Request",
            type="primary",
            key="update_support_request",
            width="stretch"
        ):
            update_support_request(selected_request, new_status)
            st.success("Support request updated.")
            st.rerun()

    except Exception as exc:
        st.error(f"Unable to load communication center: {exc}")


# ============================================================
# HR DASHBOARD
# ============================================================

def hr_dashboard():

    st.title(
        "HR Dashboard"
    )

    st.success(
        "HR authenticated successfully."
    )

    if st.sidebar.button(
        "HR Logout",
        width="stretch"
    ):

        st.session_state.hr_logged_in = False
        st.session_state.last_activity = None
        st.session_state.previous_refresh_count = None

        st.rerun()

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "Command Center",
            "Create Employee",
            "Employee Records",
            "Edit Employee",
            "Communications"
        ]
    )

    with tab1:

        hr_command_center()

    with tab2:

        hr_create_employee()

    with tab3:

        hr_view_employees()

    with tab4:

        hr_edit_employee()

    with tab5:

        hr_communication_center()


# ============================================================
# EMPLOYEE LOGIN
# ============================================================

def employee_login():

    st.title(
        "Employee Onboarding Portal"
    )

    st.subheader(
        "Employee Login"
    )

    st.info(
        "Use the Work Email and password "
        "provided by HR."
    )

    with st.form(
        "employee_login_form"
    ):

        work_email = st.text_input(
            "Work Email *"
        )

        password = st.text_input(
            "Password *",
            type="password"
        )

        login = st.form_submit_button(
            "Continue",
            type="primary"
        )

    if not login:
        return

    valid, work_email_result = validate_email_address(
        work_email
    )

    if not valid:

        st.error(
            work_email_result
        )

        return

    work_email = work_email_result

    try:

        employee = authenticate_employee(
            work_email,
            password
        )

        if employee is None:

            st.error(
                "Work Email or password is incorrect."
            )

            return

        st.session_state.employee_logged_in = True
        st.session_state.employee_id = employee.get("EMPLOYEE_ID")
        st.session_state.employee_edit_mode = bool(
            employee.get("EDIT_ALLOWED")
        ) or not onboarding_complete(employee)
        mark_activity()

        st.rerun()

    except Exception as exc:

        st.error(
            f"Unable to login: {exc}"
        )


# ============================================================
# EMPLOYEE ONBOARDING FORM
# ============================================================

def render_employee_dashboard(employee):

    completion, status, risk = employee_profile_metrics(employee)
    st.subheader("My Onboarding Dashboard")

    metric_columns = st.columns(4)
    metric_columns[0].metric("Completion", f"{completion}%")
    metric_columns[1].metric("Status", status)
    metric_columns[2].metric("Risk", risk)
    metric_columns[3].metric(
        "Edit Access",
        "Approved" if employee.get("EDIT_ALLOWED") else "Not approved"
    )
    st.progress(completion / 100)

    checklist = [
        ("Personal details", ["FIRST_NAME", "LAST_NAME", "DATE_OF_BIRTH", "GENDER"]),
        ("Contact details", ["PERSONAL_EMAIL", "PHONE"]),
        ("Address", ["ADDRESS_LINE", "CITY", "STATE", "COUNTRY", "POSTAL_CODE"]),
        ("Employment details", ["WORK_EMAIL", "DEPARTMENT", "DESIGNATION", "SALARY"]),
        ("Emergency contact", ["EMERGENCY_CONTACT_NAME", "EMERGENCY_CONTACT_RELATION", "EMERGENCY_CONTACT_PHONE", "BLOOD_GROUP"])
    ]
    checklist_rows = []
    for label, fields in checklist:
        complete = all(clean(employee.get(field)) for field in fields)
        checklist_rows.append({
            "Section": label,
            "Status": "Complete" if complete else "Action required"
        })
    st.dataframe(
        pd.DataFrame(checklist_rows),
        hide_index=True,
        width="stretch"
    )


def render_employee_first_day(employee):

    st.subheader("First-Day Readiness")
    joining_date = employee.get("JOINING_DATE")
    if joining_date:
        days = (joining_date - date.today()).days
        countdown = "Today" if days == 0 else (
            f"{days} days" if days > 0 else "Already started"
        )
    else:
        countdown = "Joining date pending"

    ready_items = {
        "Joining date": bool(joining_date),
        "Reporting manager": bool(clean(employee.get("REPORTING_MANAGER"))),
        "Work location": bool(clean(employee.get("WORK_LOCATION"))),
        "Work mode": bool(clean(employee.get("WORK_MODE")))
    }
    st.info(f"Joining countdown: {countdown}")
    st.dataframe(
        pd.DataFrame([
            {"Readiness item": label, "Status": "Ready" if ready else "Pending"}
            for label, ready in ready_items.items()
        ]),
        hide_index=True,
        width="stretch"
    )


def render_employee_policies(employee_id):

    st.subheader("Policy Acknowledgment")
    try:
        acknowledged = get_policy_acknowledgments(employee_id)
        if len(acknowledged) == len(POLICIES):
            st.success("All required policies are acknowledged.")
            return

        with st.form("employee_policy_form"):
            selections = {}
            for policy_key, title, version in POLICIES:
                selections[policy_key] = st.checkbox(
                    f"I acknowledge the {title} (version {version})",
                    value=policy_key in acknowledged,
                    disabled=policy_key in acknowledged,
                    key=f"policy_{policy_key}"
                )
            submit = st.form_submit_button(
                "Acknowledge Policies",
                type="primary",
                width="stretch"
            )

        if submit:
            if not all(selections.values()):
                st.error("Please acknowledge every required policy.")
            else:
                acknowledge_policies(employee_id)
                st.success("Policies acknowledged successfully.")
                st.rerun()
    except Exception as exc:
        st.error(f"Unable to load policies: {exc}")


def render_employee_messages(employee_id):

    st.subheader("HR Communication Center")
    try:
        messages = get_employee_messages(employee_id)
        if messages.empty:
            st.info("No messages from HR yet.")
            return
        for message in messages.to_dict("records"):
            with st.container(border=True):
                st.markdown(f"**{clean(message.get('TITLE'))}**")
                st.write(clean(message.get("MESSAGE")))
                st.caption(f"Sent: {clean(message.get('CREATED_AT'))}")
    except Exception as exc:
        st.error(f"Unable to load HR messages: {exc}")


def render_employee_support(employee_id):

    st.subheader("Support Requests")
    with st.form("employee_support_form"):
        subject = st.text_input("Subject *", key="support_subject")
        description = st.text_area("Describe your issue *", key="support_description")
        submit = st.form_submit_button(
            "Submit Support Request",
            type="primary",
            width="stretch"
        )

    if submit:
        if not subject.strip() or not description.strip():
            st.error("Subject and description are required.")
        else:
            try:
                create_support_request(employee_id, subject.strip(), description.strip())
                st.success("Support request submitted.")
                st.rerun()
            except Exception as exc:
                st.error(f"Unable to submit support request: {exc}")

    try:
        requests = get_support_requests(employee_id)
        if not requests.empty:
            st.dataframe(
                requests[["REQUEST_ID", "SUBJECT", "STATUS", "CREATED_AT"]],
                hide_index=True,
                width="stretch"
            )
    except Exception as exc:
        st.error(f"Unable to load support requests: {exc}")


def render_employee_tools(employee):

    employee_id = employee.get("EMPLOYEE_ID")
    with st.expander("Policies and HR messages", expanded=False):
        render_employee_policies(employee_id)
        render_employee_messages(employee_id)

    with st.expander("Support", expanded=False):
        render_employee_support(employee_id)

    profile_data = json.dumps(
        {key: clean(value) for key, value in employee.items()},
        indent=2,
        default=str
    )
    st.download_button(
        "Download My Profile",
        data=profile_data,
        file_name=f"{employee_id}_profile.json",
        mime="application/json",
        width="stretch",
        key="download_employee_profile"
    )


def render_employee_summary(employee):

    st.subheader("Your Submitted Information")
    st.caption("You can view your own details here. Select Edit to make changes.")

    fields = [
        ("First Name", "FIRST_NAME"),
        ("Last Name", "LAST_NAME"),
        ("Date of Birth", "DATE_OF_BIRTH"),
        ("Gender", "GENDER"),
        ("Personal Email", "PERSONAL_EMAIL"),
        ("Phone", "PHONE"),
        ("Address", "ADDRESS_LINE"),
        ("City", "CITY"),
        ("State", "STATE"),
        ("Country", "COUNTRY"),
        ("Postal Code", "POSTAL_CODE"),
        ("Emergency Contact Name", "EMERGENCY_CONTACT_NAME"),
        ("Emergency Contact Relation", "EMERGENCY_CONTACT_RELATION"),
        ("Emergency Contact Phone", "EMERGENCY_CONTACT_PHONE"),
        ("Blood Group", "BLOOD_GROUP")
    ]

    left, right = st.columns(2)

    for index, (label, column) in enumerate(fields):
        target = left if index % 2 == 0 else right
        with target:
            st.text_input(
                label,
                value=clean(employee.get(column)),
                disabled=True,
                key=f"summary_{column}"
            )

    if employee.get("EDIT_REQUESTED"):
        st.info("Your edit request is waiting for HR approval.")
    else:
        reason = st.text_area(
            "Why do you need to edit your submitted details? *",
            key="edit_request_reason"
        )
        if st.button(
            "Request Permission to Edit",
            type="primary",
            width="stretch"
        ):
            if not reason.strip():
                st.error("Please provide a reason for the edit request.")
            else:
                try:
                    request_employee_edit(
                        employee.get("EMPLOYEE_ID"),
                        reason.strip()
                    )
                    st.success("Your edit request was sent to HR.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Unable to request edit permission: {exc}")

def employee_onboarding():

    employee_id = st.session_state.employee_id

    employee = get_employee(
        employee_id
    )

    if employee is None:

        st.error(
            "Employee record not found."
        )

        return

    st.title(
        "Employee Onboarding"
    )

    st.write(
        f"Employee ID: **{employee_id}**"
    )

    complete = onboarding_complete(employee)
    st.session_state.employee_edit_mode = bool(
        employee.get("EDIT_ALLOWED")
    ) or not complete

    render_employee_dashboard(employee)
    render_employee_first_day(employee)
    render_employee_tools(employee)

    if complete:

        st.success(
            "Your onboarding information is complete."
        )

    else:

        st.warning(
            "Please complete all mandatory fields."
        )

    if complete and not st.session_state.employee_edit_mode:
        render_employee_summary(employee)
        return

    # ========================================================
    # HR CONTROLLED FIELDS
    # ========================================================

    st.subheader(
        "HR Controlled Information"
    )

    st.caption(
        "These fields were entered by HR and cannot "
        "be modified by the employee."
    )

    c1, c2 = st.columns(2)

    with c1:

        st.text_input(
            "Employee ID",
            value=clean(
                employee.get(
                    "EMPLOYEE_ID"
                )
            ),
            disabled=True
        )

        st.text_input(
            "Work Email",
            value=clean(
                employee.get(
                    "WORK_EMAIL"
                )
            ),
            disabled=True
        )

        st.text_input(
            "Department",
            value=clean(
                employee.get(
                    "DEPARTMENT"
                )
            ),
            disabled=True
        )

        st.text_input(
            "Designation",
            value=clean(
                employee.get(
                    "DESIGNATION"
                )
            ),
            disabled=True
        )

        st.number_input(
            "Salary",
            min_value=0.0,
            value=float(employee.get("SALARY") or 0.0),
            format="%.2f",
            disabled=True
        )

    with c2:

        joining_date = employee.get(
            "JOINING_DATE"
        )

        st.date_input(
            "Joining Date",
            value=(
                joining_date
                if joining_date
                else date.today()
            ),
            disabled=True
        )

        st.text_input(
            "Reporting Manager",
            value=clean(
                employee.get(
                    "REPORTING_MANAGER"
                )
            ),
            disabled=True
        )

        st.text_input(
            "Work Location",
            value=clean(
                employee.get(
                    "WORK_LOCATION"
                )
            ),
            disabled=True
        )

        st.text_input(
            "Work Mode",
            value=clean(
                employee.get(
                    "WORK_MODE"
                )
            ),
            disabled=True
        )

    st.divider()

    # ========================================================
    # EMPLOYEE FIELDS
    # ========================================================

    st.subheader(
        "Personal Information"
    )

    with st.form(
        "employee_onboarding_form"
    ):

        c1, c2 = st.columns(2)

        with c1:

            first_name = st.text_input(
                "First Name *",
                value=clean(
                    employee.get(
                        "FIRST_NAME"
                    )
                )
            )

            last_name = st.text_input(
                "Last Name *",
                value=clean(
                    employee.get(
                        "LAST_NAME"
                    )
                )
            )

            existing_dob = employee.get(
                "DATE_OF_BIRTH"
            )

            date_of_birth = st.date_input(
                "Date of Birth *",
                value=(
                    existing_dob
                    if existing_dob
                    else date(2000, 1, 1)
                ),
                min_value=date(1950, 1, 1),
                max_value=date.today()
            )

            gender_options = [
                "Male",
                "Female",
                "Other",
                "Prefer not to say"
            ]

            existing_gender = clean(
                employee.get(
                    "GENDER"
                )
            )

            gender = st.selectbox(
                "Gender *",
                gender_options,
                index=(
                    gender_options.index(
                        existing_gender
                    )
                    if existing_gender
                    in gender_options
                    else 0
                )
            )

            personal_email = st.text_input(
                "Personal Email *",
                value=clean(
                    employee.get(
                        "PERSONAL_EMAIL"
                    )
                )
            )

            phone = st.text_input(
                "Phone Number *",
                value=clean(
                    employee.get(
                        "PHONE"
                    )
                ),
                placeholder="+919876543210"
            )

        with c2:

            address_line = st.text_area(
                "Address *",
                value=clean(
                    employee.get(
                        "ADDRESS_LINE"
                    )
                )
            )

            city = st.text_input(
                "City *",
                value=clean(
                    employee.get(
                        "CITY"
                    )
                )
            )

            state = st.text_input(
                "State *",
                value=clean(
                    employee.get(
                        "STATE"
                    )
                )
            )

            country = st.text_input(
                "Country *",
                value=clean(
                    employee.get(
                        "COUNTRY"
                    )
                )
            )

            postal_code = st.text_input(
                "Postal Code *",
                value=clean(
                    employee.get(
                        "POSTAL_CODE"
                    )
                )
            )

        st.subheader(
            "Emergency Contact"
        )

        e1, e2 = st.columns(2)

        with e1:

            emergency_name = st.text_input(
                "Emergency Contact Name *",
                value=clean(
                    employee.get(
                        "EMERGENCY_CONTACT_NAME"
                    )
                )
            )

            relation_options = [
                "Parent",
                "Spouse",
                "Sibling",
                "Child",
                "Relative",
                "Friend",
                "Other"
            ]

            existing_relation = clean(
                employee.get(
                    "EMERGENCY_CONTACT_RELATION"
                )
            )

            emergency_relation = st.selectbox(
                "Emergency Contact Relation *",
                relation_options,
                index=(
                    relation_options.index(
                        existing_relation
                    )
                    if existing_relation
                    in relation_options
                    else 0
                )
            )

        with e2:

            emergency_phone = st.text_input(
                "Emergency Contact Phone *",
                value=clean(
                    employee.get(
                        "EMERGENCY_CONTACT_PHONE"
                    )
                ),
                placeholder="+919876543210"
            )

            blood_options = [
                "A+",
                "A-",
                "B+",
                "B-",
                "AB+",
                "AB-",
                "O+",
                "O-"
            ]

            existing_blood = clean(
                employee.get(
                    "BLOOD_GROUP"
                )
            )

            blood_group = st.selectbox(
                "Blood Group *",
                blood_options,
                index=(
                    blood_options.index(
                        existing_blood
                    )
                    if existing_blood
                    in blood_options
                    else 0
                )
            )

        submit = st.form_submit_button(
            "Submit Onboarding",
            type="primary",
            width="stretch"
        )

    if not submit:
        return

    errors = []

    # --------------------------------------------------------
    # VALIDATE NAME
    # --------------------------------------------------------

    valid, first_name_result = validate_name(
        first_name,
        "First Name"
    )

    if not valid:
        errors.append(first_name_result)
    else:
        first_name = first_name_result

    valid, last_name_result = validate_name(
        last_name,
        "Last Name"
    )

    if not valid:
        errors.append(last_name_result)
    else:
        last_name = last_name_result

    # --------------------------------------------------------
    # DOB
    # --------------------------------------------------------

    valid, dob_result = validate_dob(
        date_of_birth
    )

    if not valid:
        errors.append(dob_result)
    else:
        date_of_birth = dob_result

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    valid, personal_email_result = validate_email_address(
        personal_email
    )

    if not valid:
        errors.append(
            f"Personal Email: {personal_email_result}"
        )
    else:
        personal_email = personal_email_result

    # --------------------------------------------------------
    # PHONE
    # --------------------------------------------------------

    valid, phone_result = validate_phone_number(
        phone
    )

    if not valid:
        errors.append(
            f"Phone: {phone_result}"
        )
    else:
        phone = phone_result

    # --------------------------------------------------------
    # POSTAL CODE
    # --------------------------------------------------------

    valid, postal_result = validate_postal_code(
        postal_code
    )

    if not valid:
        errors.append(postal_result)
    else:
        postal_code = postal_result

    # --------------------------------------------------------
    # REQUIRED TEXT FIELDS
    # --------------------------------------------------------

    required_fields = [

        (address_line, "Address"),
        (city, "City"),
        (state, "State"),
        (country, "Country"),
        (emergency_name, "Emergency Contact Name")

    ]

    for value, field_name in required_fields:

        valid, result = required(
            value,
            field_name
        )

        if not valid:
            errors.append(result)

    # --------------------------------------------------------
    # EMERGENCY PHONE
    # --------------------------------------------------------

    valid, emergency_phone_result = validate_phone_number(
        emergency_phone
    )

    if not valid:

        errors.append(
            f"Emergency Contact Phone: "
            f"{emergency_phone_result}"
        )

    else:

        emergency_phone = emergency_phone_result

    # --------------------------------------------------------
    # SELECT FIELDS
    # --------------------------------------------------------

    if not gender:
        errors.append(
            "Gender is required."
        )

    if not emergency_relation:
        errors.append(
            "Emergency Contact Relation is required."
        )

    if not blood_group:
        errors.append(
            "Blood Group is required."
        )

    # --------------------------------------------------------
    # SHOW ERRORS
    # --------------------------------------------------------

    if errors:

        st.error(
            "Please correct the following errors:"
        )

        for error in errors:
            st.error(error)

        return

    # ========================================================
    # DUPLICATE CHECKS
    # ========================================================

    try:

        if email_exists(
            personal_email,
            "PERSONAL_EMAIL",
            employee_id
        ):

            st.warning(
                "This personal email is already "
                "registered to another employee."
            )

            return

        if phone_exists(
            phone,
            employee_id
        ):

            st.warning(
                "This phone number is already "
                "registered to another employee."
            )

            return

        if phone_exists(
            emergency_phone,
            employee_id
        ):

            st.warning(
                "Emergency contact phone number "
                "is already registered."
            )

            return

        # ====================================================
        # UPDATE SAME EMPLOYEE ROW
        # ====================================================

        sql = f"""
            UPDATE {FULL_TABLE}
            SET

                FIRST_NAME = %s,
                LAST_NAME = %s,
                DATE_OF_BIRTH = %s,
                GENDER = %s,
                PERSONAL_EMAIL = %s,
                PHONE = %s,
                ADDRESS_LINE = %s,
                CITY = %s,
                STATE = %s,
                COUNTRY = %s,
                POSTAL_CODE = %s,

                EMERGENCY_CONTACT_NAME = %s,
                EMERGENCY_CONTACT_RELATION = %s,
                EMERGENCY_CONTACT_PHONE = %s,
                BLOOD_GROUP = %s,

                EDIT_ALLOWED = FALSE,
                EDIT_REQUESTED = FALSE,

                UPDATED_AT = CURRENT_TIMESTAMP(),
                SUBMITTED_AT = CURRENT_TIMESTAMP()

            WHERE EMPLOYEE_ID = %s
        """

        execute_query(
            sql,
            (
                first_name,
                last_name,
                date_of_birth,
                gender,
                personal_email,
                phone,
                address_line,
                city,
                state,
                country,
                postal_code,
                emergency_name,
                emergency_relation,
                emergency_phone,
                blood_group,
                employee_id
            ),
            fetch=False
        )

        st.success(
            "Your onboarding information has "
            "been submitted successfully."
        )

        st.session_state.employee_edit_mode = False

        st.balloons()
        st.rerun()

    except Exception as exc:

        st.error(
            f"Unable to save your information: {exc}"
        )


# ============================================================
# MAIN APPLICATION
# ============================================================

def show_hr_login():
    hr_login_page()


def main():

    if st.session_state.hr_logged_in or st.session_state.employee_logged_in:
        refresh_count = st_autorefresh(
            interval=10000,
            key="inactivity_check"
        )

        previous_refresh_count = st.session_state.get(
            "previous_refresh_count"
        )

        if previous_refresh_count is None:
            st.session_state.previous_refresh_count = refresh_count
        elif refresh_count == previous_refresh_count:
            mark_activity()
        else:
            st.session_state.previous_refresh_count = refresh_count

        if enforce_inactivity_timeout():
            return

    st.sidebar.title(
        "Employee Onboarding"
    )

    portal = st.sidebar.radio(
        "Select Portal",
        [
            "Employee Portal",
            "HR Portal"
        ]
    )

    st.sidebar.divider()

    # ========================================================
    # EMPLOYEE PORTAL
    # ========================================================

    if portal == "Employee Portal":

        if st.session_state.employee_logged_in:

            if st.sidebar.button(
                "Employee Logout",
                width="stretch"
            ):

                st.session_state.employee_logged_in = False
                st.session_state.employee_id = None
                st.session_state.employee_edit_mode = False
                st.session_state.last_activity = None
                st.session_state.previous_refresh_count = None

                st.rerun()

            employee_onboarding()

        else:

            employee_login()

    # ========================================================
    # HR PORTAL
    # ========================================================

    elif portal == "HR Portal":

        if st.session_state.hr_logged_in:

            hr_dashboard()

        else:

            show_hr_login()
            st.stop()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as exc:

        st.error(
            "Application error:"
        )

        st.exception(exc)