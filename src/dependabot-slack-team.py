import os
import json
import base64
import urllib3
import boto3
import logging
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import time
import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

GITHUB_ORG = os.environ["GITHUB_ORG"]
SEVERITY_FILTER = [
    s.strip().lower()
    for s in os.environ.get("SEVERITY_FILTER", "critical").split(",")
]

http = urllib3.PoolManager()
HEADERS = None
TEAM_TO_CHANNEL = {}


def filter_dependabot_alerts(alerts):
    return [
        a
        for a in alerts
        if a.get("security_advisory", {}).get("severity", "").lower()
        in SEVERITY_FILTER
    ]


def get_github_token():
    region_name = os.environ.get("AWS_REGION", "us-east-1")
    secrets_client = boto3.client("secretsmanager", region_name=region_name)

    try:
        # Retrieve App ID
        app_id_response = secrets_client.get_secret_value(
            SecretId=f"{GITHUB_ORG}/GITHUB_APP_ID"
        )
        app_id = app_id_response["SecretString"].strip()
        logger.info(f"Using GitHub App ID: {app_id}")

        # Retrieve PEM key as a raw multiline string
        pem_response = secrets_client.get_secret_value(
            SecretId=f"{GITHUB_ORG}/GITHUB_APP_PEM"
        )
        pem_key = pem_response["SecretString"]
        logger.info(
            "GitHub App PEM key retrieved successfully. {pem_key[:30]}..."
        )

        # Create JWT
        now = int(time.time())
        logger.info(
            "JWT timestamp: %s UTC",
            datetime.utcfromtimestamp(now).isoformat(),
        )
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": app_id,
        }

        private_key = serialization.load_pem_private_key(
            pem_key.encode("utf-8"), password=None, backend=default_backend()
        )
        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
        # Ensure string
        if isinstance(jwt_token, bytes):
            jwt_token = jwt_token.decode("utf-8")

        logger.info("JWT token created successfully.")
        print()
        logger.info(f"JWT token: {jwt_token[:30]}... (truncated for security)")
        print()

        # Exchange for installation token
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
        }
        r = http.request(
            "GET",
            "https://api.github.com/app/installations",
            headers=headers,
        )
        if r.status != 200:
            raise Exception(
                f"Failed to list installations: {r.status} {r.data.decode()}"
            )

        installations = json.loads(r.data.decode("utf-8"))
        installation_id = installations[0]["id"]

        r = http.request(
            "POST",
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers=headers,
        )
        if r.status != 201:
            raise Exception(
                f"Failed to get installation token: {r.status} {r.data.decode()}"
            )

        token_data = json.loads(r.data.decode("utf-8"))
        return token_data["token"]

    except ClientError as e:
        raise RuntimeError(f"Error retrieving GitHub App credentials: {e}")
    except Exception as e:
        raise RuntimeError(f"GitHub App authentication failed: {e}")


def load_team_to_channel_mapping(
    secret_name=f"{GITHUB_ORG}/TEAM_TO_CHANNEL", region_name=None
):
    if not region_name:
        region_name = os.environ.get("AWS_REGION", "us-east-1")
    client = boto3.client("secretsmanager", region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString")
        mapping = json.loads(secret_string)
        logger.info("TEAM_TO_CHANNEL mapping loaded from Secrets Manager.")
        return mapping
    except ClientError as e:
        logger.error(f"Error retrieving TEAM_TO_CHANNEL mapping: {e}")
        return {}


def init_headers():
    global HEADERS
    token = get_github_token()
    HEADERS = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def get_dependabot_alerts(repo):
    alerts = []
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{repo}/dependabot/alerts?state=open&per_page=100"

    while url:
        r = http.request("GET", url, headers=HEADERS, preload_content=False)
        try:
            body = r.read()
            text_body = body.decode("utf-8") if body else ""

            if r.status != 200:
                logger.warning(
                    f"Failed to fetch alerts for {repo}: {r.status} {text_body}"
                )
                break

            if not text_body:
                logger.warning(
                    f"No data received for dependabot alerts in {repo}"
                )
                break

            alerts.extend(json.loads(text_body))

            # Parse the Link header for pagination
            link_header = r.headers.get("Link")
            next_url = None

            if link_header:
                links = link_header.split(",")
                for link in links:
                    parts = link.split(";")
                    if len(parts) == 2 and 'rel="next"' in parts[1]:
                        next_url = parts[0].strip().strip("<>")
                        break

            url = next_url

        finally:
            r.release_conn()

    return alerts


def get_codeowners_owner(repo):
    url = f"https://api.github.com/repos/{GITHUB_ORG}/{repo}/contents/.github/CODEOWNERS"
    r = http.request("GET", url, headers=HEADERS)
    if r.status != 200:
        logger.info(f"No CODEOWNERS file found in {repo}.")
        return None

    data = json.loads(r.data.decode("utf-8"))
    decoded = base64.b64decode(data["content"]).decode("utf-8")

    wildcard_owner = None
    first_valid_owner = None

    for line in decoded.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) < 2:
                continue
            owners = [p for p in parts[1:] if p.startswith("@")]
            if not owners:
                continue
            team_slug = owners[0].split("/")[-1]
            if parts[0] == "*":
                wildcard_owner = team_slug
            elif not first_valid_owner:
                first_valid_owner = team_slug

    if wildcard_owner:
        return wildcard_owner
    elif first_valid_owner:
        return first_valid_owner
    else:
        return None


def format_slack_message(repo, owner, alerts):
    severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    severity_emojis = {
        "critical": "🔥",
        "high": "⚠️",
        "medium": "🟡",
        "low": "🟢",
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y-%b-%d %H:%M:%S UTC")

    alerts.sort(
        key=lambda a: severity_order.get(
            a.get("security_advisory", {}).get("severity", "").lower(), 99
        )
    )

    counts = {}
    for a in alerts:
        sev = a["security_advisory"]["severity"].lower()
        counts[sev] = counts.get(sev, 0) + 1

    total_alerts = sum(counts.values())

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{repo}* — CODEOWNERS: `{owner}`\n"
                    f"_{timestamp}_\n"
                    f"Dependabot alert summary (filtered: {', '.join(SEVERITY_FILTER)}):\n"
                    f"*Total alerts: {total_alerts}*"
                ),
            },
        }
    ]

    for sev in sorted(counts, key=lambda s: severity_order.get(s, 99)):
        emoji = severity_emojis.get(sev, "")
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{emoji} {sev.title()}*: {counts[sev]} alert(s)",
                },
            }
        )

        for alert in [
            a
            for a in alerts
            if a["security_advisory"]["severity"].lower() == sev
        ][:10]:
            advisory = alert["security_advisory"]
            dependency = alert["dependency"]["package"]["name"]
            summary = advisory["summary"]
            url = alert.get(
                "html_url",
                f"https://github.com/{GITHUB_ORG}/{repo}/security/dependabot",
            )

            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *<{url}|{dependency}>*: {summary} _(Severity: {sev})_",
                    },
                }
            )

    return {"blocks": blocks}


def send_to_slack(message, channel):
    payload = {
        "channel": channel,
        **message,
    }
    encoded = json.dumps(payload).encode("utf-8")
    r = http.request(
        "POST",
        channel,
        body=encoded,
        headers={"Content-Type": "application/json"},
        preload_content=False,
    )

    try:
        r.read()  # Read and discard response data
    finally:
        r.release_conn()

    logger.info(f"Slack webhook returned status: {r.status}")


def group_by_owner(repo_data):
    grouped = {}
    for entry in repo_data:
        owner = entry["owner"]
        grouped.setdefault(owner, []).append(entry)
    return grouped


def get_all_non_archived_repos():
    repos = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/orgs/{GITHUB_ORG}/repos?per_page={per_page}&page={page}"
        r = http.request("GET", url, headers=HEADERS, preload_content=False)
        try:
            body = r.read()
            if r.status != 200:
                logger.error(
                    f"Failed to fetch repositories: {r.status} {body.decode()}"
                )
                break

            data = json.loads(body.decode("utf-8"))
        finally:
            r.release_conn()

        if not data:
            break

        for repo in data:
            if not repo.get("archived", False):
                repos.append(repo["name"])

        page += 1

    logger.info(f"Found {len(repos)} non-archived repositories.")
    return repos


def lambda_handler(event, context):
    init_headers()
    repos = get_all_non_archived_repos()

    if not repos:
        logger.error("Repository list is empty.")
        raise ValueError("Repository list is empty")

    global TEAM_TO_CHANNEL
    TEAM_TO_CHANNEL = load_team_to_channel_mapping()
    logger.info("TEAM_TO_CHANNEL mapping loaded.")
    logger.info("*" * 20)
    logger.info(f"TEAM_TO_CHANNEL: {TEAM_TO_CHANNEL}")
    logger.info("*" * 20)

    repo_data = []

    for repo in repos:
        alerts = get_dependabot_alerts(repo)
        owner = get_codeowners_owner(repo) or "security"
        logger.info("*" * 20)
        logger.info(f"Repo: {repo}, Owner: {owner}, Alerts: {len(alerts)}")
        repo_data.append({"repo": repo, "owner": owner, "alerts": alerts})

    grouped = group_by_owner(repo_data)

    for owner, entries in grouped.items():
        if owner not in TEAM_TO_CHANNEL:
            logger.warning(
                f"No Slack channel mapping for '{owner}', using default."
            )
            logger.warning(
                f"Assigning owner '{owner}' to fallback team 'security'."
            )
            channel = TEAM_TO_CHANNEL.get("security", "#default-channel")
            owner = "security"
        else:
            channel = TEAM_TO_CHANNEL[owner]

        for entry in entries:
            filtered_alerts = filter_dependabot_alerts(entry["alerts"])
            if not filtered_alerts:
                logger.info(
                    f"Skipping {entry['repo']} — no alerts matching filter: {SEVERITY_FILTER}"
                )
                continue

            logger.info(
                f"Repo: {entry['repo']}, Owner: {entry['owner']}, channel: {channel}"
            )
            message = format_slack_message(
                entry["repo"], owner, filtered_alerts
            )
            send_to_slack(message, channel)
            time.sleep(0.5)

    return {
        "statusCode": 200,
        "body": json.dumps({"repos_processed": len(repos)}),
    }
