#!/usr/bin/env python3
"""
Identifica l'account AWS che ha inviato un'email tramite SES,
partendo dagli header dell'email, Message-ID, IP o altri indizi.

Strategia di tracciamento:
1. Parsing header email -> estrae X-SES-MESSAGE-ID, feedback-id, Return-Path, regione
2. feedback-id -> spesso contiene direttamente l'AWS Account ID
3. Return-Path -> rivela la regione SES usata
4. Source IP -> verifica se appartiene ai range SES di AWS
5. Con il SES Message-ID, cerca in CloudTrail di ogni account per l'evento SendEmail
6. Cerca anche nei Message Insights (VDM) per account con VDM attivo

Uso:
    # Passa direttamente gli header (file .eml o .txt con gli header)
    python ses_trace.py --headers-file email_headers.txt

    # Passa i singoli valori se li hai già estratti
    python ses_trace.py --message-id "0100018f1234abcd-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-000000@eu-west-1.amazonses.com"
    python ses_trace.py --message-id "0100018f1234abcd" --ip 54.240.10.123
    python ses_trace.py --feedback-id "1.eu-west-1.abc123def456+:0:12345678:111122223333"

    # Opzioni
    python ses_trace.py --headers-file headers.txt --role-name AdminRole --profile prod
    python ses_trace.py --message-id "xxx" --regions eu-west-1,us-east-1 --days 30

Prerequisiti:
    - pip install boto3 requests
    - Credenziali AWS del master account dell'organizzazione
"""

import argparse
import email
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


ALL_SES_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-south-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-northeast-2", "ap-northeast-3",
    "ca-central-1", "sa-east-1", "me-south-1", "af-south-1",
]

# AWS SES IP ranges noti (prefissi comuni)
SES_IP_PREFIXES = [
    "54.240.0.0/18", "69.169.224.0/20", "198.51.100.0/24",
    "199.255.192.0/22", "23.251.224.0/19",
]


# ---------------------------------------------------------------------------
# Parsing degli header email
# ---------------------------------------------------------------------------
def parse_headers_from_file(filepath):
    """Legge un file di header email (.eml, .txt) e estrae le info SES."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # Prova a parsare come email completa
    msg = email.message_from_string(raw)

    info = {
        "ses_message_id": None,
        "message_id": None,
        "feedback_id": None,
        "return_path": None,
        "source_ip": None,
        "from": None,
        "to": None,
        "subject": None,
        "date": None,
        "ses_region": None,
        "ses_outgoing": False,
        "ses_configuration_set": None,
        "dkim_domain": None,
        "account_id_candidates": set(),
        "raw_ses_headers": {},
    }

    # Estrai tutti gli header
    for key, value in msg.items():
        key_lower = key.lower()

        if key_lower == "x-ses-outgoing":
            info["ses_outgoing"] = True
            info["raw_ses_headers"][key] = value

        elif key_lower == "x-ses-message-id":
            info["ses_message_id"] = value.strip()
            info["raw_ses_headers"][key] = value

        elif key_lower == "message-id":
            info["message_id"] = value.strip().strip("<>")
            # Il Message-ID SES contiene la regione: xxx@region.amazonses.com
            match = re.search(r"@([a-z0-9-]+)\.amazonses\.com", value)
            if match:
                info["ses_region"] = match.group(1)
                info["ses_outgoing"] = True

        elif key_lower == "feedback-id":
            info["feedback_id"] = value.strip()
            info["raw_ses_headers"][key] = value

        elif key_lower == "return-path":
            info["return_path"] = value.strip().strip("<>")
            # Return-Path SES: xxxx@region.amazonses.com
            match = re.search(r"@([a-z0-9-]+)\.amazonses\.com", value)
            if match and not info["ses_region"]:
                info["ses_region"] = match.group(1)

        elif key_lower == "x-ses-configuration-set":
            info["ses_configuration_set"] = value.strip()
            info["raw_ses_headers"][key] = value

        elif key_lower == "from":
            info["from"] = value.strip()

        elif key_lower == "to":
            info["to"] = value.strip()

        elif key_lower == "subject":
            info["subject"] = value.strip()

        elif key_lower == "date":
            info["date"] = value.strip()

        elif key_lower == "dkim-signature":
            # Estrai il dominio DKIM (d=)
            match = re.search(r"d=([^\s;]+)", value)
            if match:
                domain = match.group(1)
                if "amazonses.com" in domain:
                    info["ses_outgoing"] = True
                else:
                    info["dkim_domain"] = domain

        # Cerca IP nei Received headers
        elif key_lower == "received":
            ip_matches = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", value)
            for ip in ip_matches:
                if not info["source_ip"] and not ip.startswith(("10.", "192.168.", "127.")):
                    info["source_ip"] = ip

        # Header specifici SES aggiuntivi
        elif key_lower.startswith("x-ses-"):
            info["raw_ses_headers"][key] = value

    # Analizza feedback-id per estrarre account ID
    if info["feedback_id"]:
        _extract_account_from_feedback_id(info)

    # Analizza Return-Path per info aggiuntive
    if info["return_path"]:
        _extract_info_from_return_path(info)

    return info


def _extract_account_from_feedback_id(info):
    """
    Il feedback-id SES ha vari formati. Spesso contiene l'account ID a 12 cifre.
    Formati comuni:
      - 1.eu-west-1.xxxx:0:xxxxxx:111122223333
      - 111122223333:config-set:xxx:xxx
      - vari formati con campi separati da ":"
    """
    fid = info["feedback_id"]

    # Cerca un numero a 12 cifre (AWS Account ID)
    matches = re.findall(r"\b(\d{12})\b", fid)
    for m in matches:
        info["account_id_candidates"].add(m)

    # Estrai regione dal feedback-id
    region_match = re.search(r"(us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-west-2|"
                             r"eu-west-3|eu-central-1|eu-south-1|eu-north-1|ap-south-1|"
                             r"ap-southeast-1|ap-southeast-2|ap-northeast-1|ap-northeast-2|"
                             r"ap-northeast-3|ca-central-1|sa-east-1|me-south-1|af-south-1)", fid)
    if region_match and not info["ses_region"]:
        info["ses_region"] = region_match.group(1)


def _extract_info_from_return_path(info):
    """Estrai info dal Return-Path SES."""
    rp = info["return_path"]
    # Formato: 010001xxxx-sender=example.com@region.amazonses.com
    # La parte prima di @ può contenere l'ID del messaggio SES
    match = re.match(r"^([a-f0-9-]+)-", rp)
    if match and not info["ses_message_id"]:
        candidate = match.group(1)
        if len(candidate) > 10:  # SES message IDs sono lunghi
            info["ses_message_id"] = candidate


def parse_manual_inputs(args):
    """Costruisci info da parametri CLI manuali."""
    info = {
        "ses_message_id": None,
        "message_id": None,
        "feedback_id": None,
        "return_path": None,
        "source_ip": args.ip if args.ip else None,
        "from": args.sender if args.sender else None,
        "to": None,
        "subject": args.subject if args.subject else None,
        "date": None,
        "ses_region": None,
        "ses_outgoing": False,
        "ses_configuration_set": None,
        "dkim_domain": None,
        "account_id_candidates": set(),
        "raw_ses_headers": {},
    }

    if args.message_id:
        mid = args.message_id.strip().strip("<>")
        info["message_id"] = mid
        # Controlla se contiene la regione
        match = re.search(r"@([a-z0-9-]+)\.amazonses\.com", mid)
        if match:
            info["ses_region"] = match.group(1)
            info["ses_outgoing"] = True
        # Se è solo l'ID SES senza @region
        if "@" not in mid:
            info["ses_message_id"] = mid

    if args.feedback_id:
        info["feedback_id"] = args.feedback_id
        _extract_account_from_feedback_id(info)

    return info


# ---------------------------------------------------------------------------
# Verifica IP SES
# ---------------------------------------------------------------------------
def check_ses_ip(ip_str):
    """Verifica se un IP appartiene ai range AWS SES."""
    if not ip_str:
        return None

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"ip": ip_str, "is_ses": False, "error": "IP non valido"}

    # Check contro prefissi SES noti
    for prefix in SES_IP_PREFIXES:
        if ip in ipaddress.ip_network(prefix):
            return {"ip": ip_str, "is_ses": True, "network": prefix}

    # Scarica e controlla i range AWS ufficiali
    if HAS_REQUESTS:
        try:
            resp = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
            data = resp.json()
            for prefix_info in data.get("prefixes", []):
                if prefix_info.get("service") in ("AMAZON_SES", "SES"):
                    if ip in ipaddress.ip_network(prefix_info["ip_prefix"]):
                        return {
                            "ip": ip_str,
                            "is_ses": True,
                            "network": prefix_info["ip_prefix"],
                            "region": prefix_info.get("region", ""),
                            "service": prefix_info["service"],
                        }
                # Anche AMAZON generico (SES usa IP dal pool AMAZON)
                if prefix_info.get("service") == "AMAZON":
                    if ip in ipaddress.ip_network(prefix_info["ip_prefix"]):
                        return {
                            "ip": ip_str,
                            "is_aws": True,
                            "is_ses": None,  # è AWS ma non confermato SES
                            "network": prefix_info["ip_prefix"],
                            "region": prefix_info.get("region", ""),
                        }
        except Exception:
            pass

    return {"ip": ip_str, "is_ses": False}


# ---------------------------------------------------------------------------
# Ricerca CloudTrail per Message-ID
# ---------------------------------------------------------------------------
def get_org_accounts(session):
    """Recupera account dall'organizzazione."""
    org = session.client("organizations")
    accounts = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":
                accounts.append(acct)
    return accounts


def assume_role(master_session, account_id, role_name):
    """Assume ruolo in un account."""
    sts = master_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="SESTrace",
        )
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError:
        return None


def search_cloudtrail_for_message(session, region, ses_message_id, sender, days):
    """
    Cerca in CloudTrail l'evento SendEmail corrispondente al Message-ID SES.
    Il Message-ID SES appare nel responseElements.messageId di CloudTrail.
    """
    results = []
    try:
        ct = session.client("cloudtrail", region_name=region)
        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        for event_name in ["SendEmail", "SendRawEmail", "SendBulkEmail",
                           "SendTemplatedEmail", "SendBulkTemplatedEmail"]:
            try:
                lookup_attrs = [
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ]

                paginator = ct.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=lookup_attrs,
                    StartTime=start_time,
                    EndTime=datetime.now(timezone.utc),
                ):
                    for event in page.get("Events", []):
                        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        resp_elem = ct_event.get("responseElements") or {}
                        req_params = ct_event.get("requestParameters") or {}

                        # Il messageId è nel responseElements
                        ct_msg_id = resp_elem.get("messageId", "")

                        # Match per Message-ID
                        match_mid = False
                        if ses_message_id:
                            if (ses_message_id in ct_msg_id
                                    or ct_msg_id in ses_message_id):
                                match_mid = True

                        # Match per sender (fallback se no Message-ID)
                        match_sender = False
                        if not ses_message_id and sender:
                            source = (
                                req_params.get("source", "")
                                or req_params.get("fromEmailAddress", "")
                                or (req_params.get("defaultContent") or {}).get("fromEmailAddress", "")
                            )
                            if sender.lower() in source.lower():
                                match_sender = True

                        if match_mid or match_sender:
                            # Estrai dettagli
                            source = (
                                req_params.get("source", "")
                                or req_params.get("fromEmailAddress", "")
                            )
                            dest = req_params.get("destination") or {}
                            to_addrs = dest.get("toAddresses", []) if isinstance(dest, dict) else []

                            subject = ""
                            msg_body = req_params.get("message") or {}
                            if isinstance(msg_body, dict):
                                subj_obj = msg_body.get("subject") or {}
                                subject = subj_obj.get("data", "") if isinstance(subj_obj, dict) else str(subj_obj)

                            user_id = ct_event.get("userIdentity") or {}

                            results.append({
                                "matched_by": "message_id" if match_mid else "sender",
                                "event_name": event_name,
                                "event_time": str(event.get("EventTime", "")),
                                "message_id": ct_msg_id,
                                "source": source,
                                "to": to_addrs[:5],
                                "subject": subject,
                                "region": region,
                                "source_ip": ct_event.get("sourceIPAddress", ""),
                                "user_agent": ct_event.get("userAgent", ""),
                                "caller_arn": user_id.get("arn", ""),
                                "caller_type": user_id.get("type", ""),
                                "caller_principal": user_id.get("principalId", ""),
                                "access_key": user_id.get("accessKeyId", ""),
                                "account_id": ct_event.get("recipientAccountId",
                                              user_id.get("accountId", "")),
                            })
            except ClientError:
                pass
    except Exception:
        pass
    return results


def search_ses_message_insights(session, region, ses_message_id):
    """Cerca un messaggio specifico via SES v2 GetMessageInsights (richiede VDM)."""
    try:
        ses = session.client("sesv2", region_name=region)
        # Verifica VDM
        account = ses.get_account()
        if account.get("VdmAttributes", {}).get("VdmEnabled") != "ENABLED":
            return None

        resp = ses.get_message_insights(MessageId=ses_message_id)
        return {
            "message_id": resp.get("MessageId", ""),
            "from": resp.get("FromEmailAddress", ""),
            "subject": resp.get("Subject", ""),
            "insights": resp.get("Insights", []),
            "headers": resp.get("EmailTags", []),
            "region": region,
        }
    except ClientError:
        return None
    except Exception:
        return None


def search_account_for_message(master_session, account, role_name, regions,
                                ses_message_id, sender, days, master_account_id):
    """Cerca il messaggio in un singolo account."""
    account_id = account["Id"]
    result = {
        "account_id": account_id,
        "account_name": account.get("Name", account_id),
        "cloudtrail_matches": [],
        "message_insights": None,
        "error": None,
    }

    if account_id == master_account_id:
        session = master_session
    else:
        session = assume_role(master_session, account_id, role_name)
        if session is None:
            result["error"] = "Impossibile assumere ruolo"
            return result

    for region in regions:
        # CloudTrail search
        ct_matches = search_cloudtrail_for_message(
            session, region, ses_message_id, sender, days
        )
        result["cloudtrail_matches"].extend(ct_matches)

        # SES Message Insights (se abbiamo il message ID esatto)
        if ses_message_id and not result["message_insights"]:
            insights = search_ses_message_insights(session, region, ses_message_id)
            if insights:
                result["message_insights"] = insights

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_header_analysis(info):
    """Stampa l'analisi degli header."""
    print("\n" + "=" * 80)
    print("ANALISI HEADER EMAIL")
    print("=" * 80)

    print(f"\n  Inviata via SES:      {'SI' if info['ses_outgoing'] else 'NON CONFERMATO'}")

    if info["from"]:
        print(f"  From:                 {info['from']}")
    if info["to"]:
        print(f"  To:                   {info['to']}")
    if info["subject"]:
        print(f"  Subject:              {info['subject']}")
    if info["date"]:
        print(f"  Date:                 {info['date']}")

    print(f"\n  --- Identificativi SES ---")
    if info["ses_message_id"]:
        print(f"  SES Message-ID:       {info['ses_message_id']}")
    if info["message_id"]:
        print(f"  Message-ID:           {info['message_id']}")
    if info["feedback_id"]:
        print(f"  Feedback-ID:          {info['feedback_id']}")
    if info["return_path"]:
        print(f"  Return-Path:          {info['return_path']}")
    if info["ses_configuration_set"]:
        print(f"  Configuration Set:    {info['ses_configuration_set']}")
    if info["ses_region"]:
        print(f"  Regione SES:          {info['ses_region']}")
    if info["source_ip"]:
        print(f"  Source IP:            {info['source_ip']}")
    if info["dkim_domain"]:
        print(f"  DKIM Domain:          {info['dkim_domain']}")

    if info["account_id_candidates"]:
        print(f"\n  >>> ACCOUNT ID TROVATI NEGLI HEADER <<<")
        for aid in info["account_id_candidates"]:
            print(f"  >>> {aid} <<<")

    if info["raw_ses_headers"]:
        print(f"\n  Header SES grezzi:")
        for k, v in info["raw_ses_headers"].items():
            print(f"    {k}: {v[:100]}")


def print_ip_analysis(ip_info):
    """Stampa l'analisi dell'IP."""
    if not ip_info:
        return
    print(f"\n  --- Analisi IP ---")
    print(f"  IP:        {ip_info['ip']}")
    if ip_info.get("is_ses"):
        print(f"  Risultato: CONFERMATO IP SES AWS")
        if ip_info.get("region"):
            print(f"  Regione:   {ip_info['region']}")
    elif ip_info.get("is_aws"):
        print(f"  Risultato: IP AWS (non confermato SES specificamente)")
        if ip_info.get("region"):
            print(f"  Regione:   {ip_info['region']}")
    else:
        print(f"  Risultato: NON appartiene ai range AWS noti")


def print_search_results(all_results, info):
    """Stampa i risultati della ricerca cross-account."""
    found = False

    for res in all_results:
        if not res["cloudtrail_matches"] and not res["message_insights"]:
            continue

        if not found:
            print(f"\n{'=' * 80}")
            print("RISULTATI RICERCA CROSS-ACCOUNT")
            print(f"{'=' * 80}")
            found = True

        print(f"\n  {'*' * 60}")
        print(f"  TROVATO in Account: {res['account_name']} ({res['account_id']})")
        print(f"  {'*' * 60}")

        if res["message_insights"]:
            mi = res["message_insights"]
            print(f"\n    [SES Message Insights]")
            print(f"    Message-ID:  {mi['message_id']}")
            print(f"    From:        {mi['from']}")
            print(f"    Subject:     {mi['subject']}")
            print(f"    Regione:     {mi['region']}")
            if mi["insights"]:
                for insight in mi["insights"]:
                    dest = insight.get("Destination", "")
                    isp = insight.get("Isp", "")
                    events = insight.get("Events", [])
                    print(f"    Destinatario: {dest} (ISP: {isp})")
                    for evt in events:
                        print(f"      {evt.get('Type','')}: {evt.get('Timestamp','')}")

        for ct in res["cloudtrail_matches"]:
            print(f"\n    [CloudTrail - {ct['matched_by']}]")
            print(f"    Evento:      {ct['event_name']}")
            print(f"    Timestamp:   {ct['event_time']}")
            print(f"    Message-ID:  {ct['message_id']}")
            print(f"    From:        {ct['source']}")
            if ct["subject"]:
                print(f"    Subject:     {ct['subject']}")
            if ct["to"]:
                print(f"    To:          {', '.join(ct['to'])}")
            print(f"    Regione:     {ct['region']}")
            print(f"    Source IP:   {ct['source_ip']}")
            print(f"    Caller ARN:  {ct['caller_arn']}")
            print(f"    Caller Type: {ct['caller_type']}")
            print(f"    User Agent:  {ct['user_agent']}")
            print(f"    Account ID:  {ct['account_id']}")

    if not found:
        print(f"\n{'=' * 80}")
        print("NESSUN MATCH TROVATO nella ricerca cross-account")
        print(f"{'=' * 80}")
        print("\n  Possibili cause:")
        print("  - L'evento CloudTrail e' piu' vecchio di --days")
        print("  - Il ruolo non ha accesso a CloudTrail in quegli account")
        print("  - Il Message-ID non corrisponde (controlla il formato)")
        print("  - L'email non e' stata inviata tramite SES")

        if info.get("account_id_candidates"):
            print(f"\n  SUGGERIMENTO: gli header contengono questi possibili Account ID:")
            for aid in info["account_id_candidates"]:
                print(f"    -> {aid}")
            print("  Prova: --account-ids " + ",".join(info["account_id_candidates"]))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Traccia un'email SES e identifica l'account AWS mittente"
    )

    # Input: header file o valori manuali
    input_group = parser.add_argument_group("Input (header file O valori manuali)")
    input_group.add_argument("--headers-file", "-H",
                             help="File con gli header email (.eml o .txt)")
    input_group.add_argument("--message-id", "-m",
                             help="Message-ID o X-SES-MESSAGE-ID")
    input_group.add_argument("--feedback-id", "-f",
                             help="Valore dell'header feedback-id")
    input_group.add_argument("--ip", "-i",
                             help="IP sorgente dell'email")
    input_group.add_argument("--sender", "-s",
                             help="Indirizzo email del mittente")
    input_group.add_argument("--subject", "-S",
                             help="Oggetto dell'email")

    # Opzioni AWS
    aws_group = parser.add_argument_group("Opzioni AWS")
    aws_group.add_argument("--role-name", "-r", default="OrganizationAccountAccessRole",
                           help="Ruolo da assumere (default: OrganizationAccountAccessRole)")
    aws_group.add_argument("--profile", "-p", default=None,
                           help="AWS CLI profile")
    aws_group.add_argument("--account-ids", default="",
                           help="Cerca solo in questi account (virgola-separati)")
    aws_group.add_argument("--days", "-d", type=int, default=14,
                           help="Giorni indietro per CloudTrail (default: 14)")
    aws_group.add_argument("--regions", default="",
                           help="Regioni da cercare (default: auto-detect o tutte)")
    aws_group.add_argument("--threads", "-t", type=int, default=10,
                           help="Thread paralleli (default: 10)")

    # Modalità
    mode_group = parser.add_argument_group("Modalita")
    mode_group.add_argument("--analyze-only", action="store_true",
                            help="Solo analisi header, senza ricerca cross-account")
    mode_group.add_argument("--output", "-o", default="",
                            help="Esporta risultati in JSON")

    args = parser.parse_args()

    if not any([args.headers_file, args.message_id, args.feedback_id, args.ip, args.sender]):
        parser.error("Specificare --headers-file o almeno uno tra --message-id, --feedback-id, --ip, --sender")

    # Step 1: Parse degli header
    print("=" * 80)
    print("SES TRACE - Identificazione account mittente")
    print("=" * 80)

    if args.headers_file:
        print(f"\n  Analisi header da: {args.headers_file}")
        info = parse_headers_from_file(args.headers_file)
    else:
        info = parse_manual_inputs(args)

    # Sovrascrivi con input manuali se forniti (hanno priorita)
    if args.message_id and not info["ses_message_id"]:
        mid = args.message_id.strip().strip("<>")
        if "@" not in mid:
            info["ses_message_id"] = mid
        else:
            info["message_id"] = mid
            match = re.search(r"@([a-z0-9-]+)\.amazonses\.com", mid)
            if match:
                info["ses_region"] = match.group(1)
    if args.ip:
        info["source_ip"] = args.ip
    if args.sender:
        info["from"] = args.sender
    if args.subject:
        info["subject"] = args.subject
    if args.feedback_id:
        info["feedback_id"] = args.feedback_id
        _extract_account_from_feedback_id(info)

    # Stampa analisi header
    print_header_analysis(info)

    # Step 2: Verifica IP
    ip_info = check_ses_ip(info["source_ip"])
    if ip_info:
        print_ip_analysis(ip_info)
        if ip_info.get("region") and not info["ses_region"]:
            info["ses_region"] = ip_info["region"]

    # Se troviamo l'Account ID direttamente dagli header, comunicalo subito
    if info["account_id_candidates"]:
        print(f"\n  {'!' * 60}")
        print(f"  ACCOUNT ID IDENTIFICATO DAGLI HEADER: {', '.join(info['account_id_candidates'])}")
        print(f"  {'!' * 60}")

    if args.analyze_only:
        print("\n  (--analyze-only: ricerca cross-account saltata)")
        return

    # Step 3: Ricerca cross-account
    print(f"\n{'=' * 80}")
    print("RICERCA CROSS-ACCOUNT")
    print(f"{'=' * 80}")

    # Determina regioni da cercare
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    elif info["ses_region"]:
        # Se conosciamo la regione, cerchiamo solo li (molto piu veloce)
        regions = [info["ses_region"]]
        print(f"  Regione identificata dagli header: {info['ses_region']}")
    else:
        regions = ALL_SES_REGIONS
    print(f"  Regioni da cercare: {', '.join(regions)}")

    # Session master
    try:
        session_kwargs = {"profile_name": args.profile} if args.profile else {}
        master_session = boto3.Session(**session_kwargs)
        sts = master_session.client("sts")
        identity = sts.get_caller_identity()
        master_account_id = identity["Account"]
        print(f"  Master Account: {master_account_id}")
    except (NoCredentialsError, ClientError) as e:
        print(f"\n  [ERRORE] {e}")
        sys.exit(1)

    # Lista account
    if args.account_ids:
        account_ids = [a.strip() for a in args.account_ids.split(",") if a.strip()]
        accounts = [{"Id": aid, "Name": aid, "Email": ""} for aid in account_ids]
    elif info["account_id_candidates"]:
        # Se abbiamo candidati dagli header, cerchiamo prima quelli
        accounts = [{"Id": aid, "Name": f"(da header)", "Email": ""}
                    for aid in info["account_id_candidates"]]
        print(f"  Cercando prima negli account identificati dagli header...")
    else:
        try:
            accounts = get_org_accounts(master_session)
        except ClientError:
            accounts = [{"Id": master_account_id, "Name": "Current", "Email": ""}]
    print(f"  Account da cercare: {len(accounts)}")

    ses_message_id = info.get("ses_message_id") or ""
    sender = info.get("from") or ""
    days = min(max(args.days, 1), 90)

    if not ses_message_id and not sender:
        print("\n  [!] Nessun Message-ID o sender disponibile per la ricerca CloudTrail.")
        print("  Fornisci --message-id o --sender per cercare.")
        return

    print(f"  Cerco per: {f'Message-ID={ses_message_id}' if ses_message_id else f'Sender={sender}'}")
    print(f"  Ultimi {days} giorni\n")

    # Ricerca parallela
    all_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for account in accounts:
            future = executor.submit(
                search_account_for_message, master_session, account, args.role_name,
                regions, ses_message_id, sender, days, master_account_id,
            )
            futures[future] = account

        for i, future in enumerate(as_completed(futures), 1):
            account = futures[future]
            try:
                result = future.result()
                all_results.append(result)
                n = len(result["cloudtrail_matches"]) + (1 if result["message_insights"] else 0)
                mark = " *** MATCH ***" if n else ""
                print(f"  [{i}/{len(accounts)}] {account.get('Name', account['Id'])} "
                      f"({account['Id']}){mark}")

                # Se troviamo un match e stavamo cercando solo i candidati header,
                # non serve continuare
                if n and info["account_id_candidates"]:
                    break
            except Exception as e:
                print(f"  [{i}/{len(accounts)}] {account.get('Name', account['Id'])} - ERRORE: {e}")

    # Se non trovato nei candidati, cerca in tutti gli account
    found_any = any(
        r["cloudtrail_matches"] or r["message_insights"] for r in all_results
    )
    if not found_any and info["account_id_candidates"] and not args.account_ids:
        print(f"\n  Non trovato negli account candidati. Cerco in tutti gli account...")
        try:
            all_accounts = get_org_accounts(master_session)
            remaining = [a for a in all_accounts
                         if a["Id"] not in info["account_id_candidates"]]

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {}
                for account in remaining:
                    future = executor.submit(
                        search_account_for_message, master_session, account,
                        args.role_name, regions, ses_message_id, sender, days,
                        master_account_id,
                    )
                    futures[future] = account

                for i, future in enumerate(as_completed(futures), 1):
                    account = futures[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        n = len(result["cloudtrail_matches"]) + (1 if result["message_insights"] else 0)
                        mark = " *** MATCH ***" if n else ""
                        print(f"  [{i}/{len(remaining)}] "
                              f"{account.get('Name', account['Id'])}{mark}")
                    except Exception:
                        pass
        except ClientError:
            pass

    # Output
    print_search_results(all_results, info)

    if args.output:
        export_data = {
            "header_analysis": {k: (list(v) if isinstance(v, set) else v) for k, v in info.items()},
            "ip_analysis": ip_info,
            "search_results": all_results,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n  Esportato in: {args.output}")


if __name__ == "__main__":
    main()
