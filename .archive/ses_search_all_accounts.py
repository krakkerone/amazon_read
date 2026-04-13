#!/usr/bin/env python3
"""
Cerca attività SES in tutti gli account AWS dell'organizzazione.

Dal master account assume un ruolo in ogni account membro e:
1. Cerca identità SES verificate che corrispondono al sender
2. Usa SES v2 CreateExportJob (Message Insights) per cercare email per sender/oggetto
3. Controlla la suppression list SES per destinatari problematici
4. (Fallback) CloudTrail per eventi SendEmail se --cloudtrail è attivo

Uso:
    python ses_search_all_accounts.py --sender "noreply@example.com"
    python ses_search_all_accounts.py --subject "Fattura"
    python ses_search_all_accounts.py --sender "noreply@example.com" --subject "Fattura"
    python ses_search_all_accounts.py --sender "noreply@example.com" --cloudtrail
    python ses_search_all_accounts.py --sender "noreply@example.com" --days 30 --regions eu-west-1,us-east-1

Prerequisiti:
    - Credenziali AWS configurate per il master account dell'organizzazione
    - Un ruolo IAM assumibile in ogni account membro (default: OrganizationAccountAccessRole)
    - pip install boto3
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


ALL_SES_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-south-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-northeast-2", "ap-northeast-3",
    "ca-central-1", "sa-east-1", "me-south-1", "af-south-1",
    "il-central-1",
]


def get_org_accounts(session):
    """Recupera tutti gli account attivi dall'organizzazione AWS."""
    org = session.client("organizations")
    accounts = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":
                accounts.append(acct)
    return accounts


def assume_role(master_session, account_id, role_name):
    """Assume un ruolo in un account target e restituisce una session boto3."""
    sts = master_session.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="SESSearch")
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError as e:
        return None


def get_session_for_account(master_session, account_id, role_name, master_account_id):
    """Restituisce la session corretta (master o assumed role)."""
    if account_id == master_account_id:
        return master_session
    return assume_role(master_session, account_id, role_name)


# ---------------------------------------------------------------------------
# 1. SES v2 - Identità verificate
# ---------------------------------------------------------------------------
def search_ses_identities(session, region, sender_filter):
    """Cerca identità SES v2 verificate che matchano il sender filter."""
    results = []
    try:
        ses = session.client("sesv2", region_name=region)
        paginator = ses.get_paginator("list_email_identities")
        for page in paginator.paginate():
            for identity in page.get("EmailIdentities", []):
                name = identity["IdentityName"]
                if sender_filter.lower() in name.lower() or name.lower() in sender_filter.lower():
                    results.append({
                        "identity": name,
                        "type": identity.get("IdentityType", "UNKNOWN"),
                        "sending_enabled": identity.get("SendingEnabled", False),
                        "region": region,
                    })
    except ClientError:
        pass
    return results


# ---------------------------------------------------------------------------
# 2. SES v2 - Stato account e sending statistics
# ---------------------------------------------------------------------------
def get_ses_account_info(session, region):
    """Recupera info sull'account SES: stato invio, quota, VDM."""
    try:
        ses = session.client("sesv2", region_name=region)
        account = ses.get_account()
        return {
            "region": region,
            "sending_enabled": account.get("SendingEnabled", False),
            "production_access": account.get("ProductionAccessEnabled", False),
            "max_send_rate": account.get("SendQuota", {}).get("MaxSendRate", 0),
            "max_24h": account.get("SendQuota", {}).get("Max24HourSend", 0),
            "sent_last_24h": account.get("SendQuota", {}).get("SentLast24Hours", 0),
            "vdm_enabled": account.get("VdmAttributes", {}).get("VdmEnabled", "DISABLED") == "ENABLED",
        }
    except ClientError:
        return None


# ---------------------------------------------------------------------------
# 3. SES v2 - Message Insights via CreateExportJob (richiede VDM)
# ---------------------------------------------------------------------------
def search_message_insights_export(session, region, sender_filter, subject_filter, days):
    """
    Usa SES v2 CreateExportJob con MessageInsights per cercare email.
    Questo è l'UNICO endpoint SES nativo che permette di cercare email inviate
    per sender/subject. Richiede VDM (Virtual Deliverability Manager) attivo.
    Restituisce i risultati dell'export (asincrono, attende il completamento).
    """
    results = []
    try:
        ses = session.client("sesv2", region_name=region)

        # Verifica VDM attivo
        account = ses.get_account()
        vdm = account.get("VdmAttributes", {}).get("VdmEnabled", "DISABLED")
        if vdm != "ENABLED":
            return results, "VDM_DISABLED"

        start_date = datetime.now(timezone.utc) - timedelta(days=min(days, 30))
        end_date = datetime.now(timezone.utc)

        # Costruisci filtro Message Insights
        filter_obj = {}
        if sender_filter:
            filter_obj["FromEmailAddress"] = [sender_filter]
        if subject_filter:
            filter_obj["Subject"] = [subject_filter]

        if not filter_obj:
            return results, "NO_FILTER"

        # Crea l'export job
        try:
            resp = ses.create_export_job(
                ExportDataSource={
                    "MessageInsightsDataSource": {
                        "StartDate": start_date,
                        "EndDate": end_date,
                        "Include": filter_obj,
                    }
                },
                ExportDestination={
                    "DataFormat": "JSON",
                },
            )
            job_id = resp["JobId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            return results, f"EXPORT_ERROR:{code}"

        # Attendi completamento (max 60 secondi)
        for _ in range(12):
            time.sleep(5)
            try:
                job = ses.get_export_job(JobId=job_id)
                status = job.get("JobStatus", "")
                if status == "COMPLETED":
                    # Recupera URL dei risultati
                    metrics = job.get("Statistics", {})
                    export_url = job.get("ExportDestination", {}).get("S3Url", "")
                    processed = metrics.get("ProcessedRecordsCount", 0)
                    exported = metrics.get("ExportedRecordsCount", 0)
                    results.append({
                        "job_id": job_id,
                        "status": "COMPLETED",
                        "processed_records": processed,
                        "exported_records": exported,
                        "s3_url": export_url,
                        "region": region,
                    })
                    return results, "OK"
                elif status == "FAILED":
                    error = job.get("FailureInfo", {}).get("Message", "Unknown")
                    return results, f"JOB_FAILED:{error}"
                elif status == "CANCELLED":
                    return results, "JOB_CANCELLED"
            except ClientError:
                break

        return results, "TIMEOUT"

    except ClientError as e:
        return results, f"ERROR:{e.response['Error']['Code']}"
    except Exception as e:
        return results, f"ERROR:{str(e)}"


# ---------------------------------------------------------------------------
# 4. SES v2 - Suppression list
# ---------------------------------------------------------------------------
def search_suppression_list(session, region, sender_filter):
    """Cerca nella suppression list SES v2 (email che non ricevono più)."""
    results = []
    try:
        ses = session.client("sesv2", region_name=region)
        paginator = ses.get_paginator("list_suppressed_destinations")
        for page in paginator.paginate():
            for dest in page.get("SuppressedDestinationSummaries", []):
                addr = dest.get("EmailAddress", "")
                if sender_filter and sender_filter.lower() in addr.lower():
                    results.append({
                        "email": addr,
                        "reason": dest.get("Reason", ""),
                        "last_update": str(dest.get("LastUpdateTime", "")),
                        "region": region,
                    })
    except ClientError:
        pass
    return results


# ---------------------------------------------------------------------------
# 5. SES v2 - Configuration sets e event destinations
# ---------------------------------------------------------------------------
def list_configuration_sets_with_events(session, region):
    """Lista i configuration set SES e le loro event destinations (per capire dove vanno i log)."""
    results = []
    try:
        ses = session.client("sesv2", region_name=region)
        paginator = ses.get_paginator("list_configuration_sets")
        for page in paginator.paginate():
            for cs_name in page.get("ConfigurationSets", []):
                try:
                    cs = ses.get_configuration_set(ConfigurationSetName=cs_name)
                    # Recupera event destinations
                    events_resp = ses.get_configuration_set_event_destinations(
                        ConfigurationSetName=cs_name
                    )
                    destinations = events_resp.get("EventDestinations", [])
                    for dest in destinations:
                        dest_info = {
                            "config_set": cs_name,
                            "destination_name": dest.get("Name", ""),
                            "enabled": dest.get("Enabled", False),
                            "events": dest.get("MatchingEventTypes", []),
                            "region": region,
                        }
                        # Identifica dove vanno i log
                        if "CloudWatchDestination" in dest:
                            dest_info["type"] = "CloudWatch"
                        elif "KinesisFirehoseDestination" in dest:
                            dest_info["type"] = "KinesisFirehose"
                            dest_info["stream"] = dest["KinesisFirehoseDestination"].get(
                                "DeliveryStreamArn", ""
                            )
                        elif "SnsDestination" in dest:
                            dest_info["type"] = "SNS"
                            dest_info["topic"] = dest["SnsDestination"].get("TopicArn", "")
                        elif "PinpointDestination" in dest:
                            dest_info["type"] = "Pinpoint"
                        elif "EventBridgeDestination" in dest:
                            dest_info["type"] = "EventBridge"
                        else:
                            dest_info["type"] = "Unknown"
                        results.append(dest_info)
                except ClientError:
                    pass
    except ClientError:
        pass
    return results


# ---------------------------------------------------------------------------
# 6. (Fallback opzionale) CloudTrail
# ---------------------------------------------------------------------------
def search_cloudtrail_ses_events(session, region, sender_filter, subject_filter, days):
    """Cerca eventi CloudTrail SendEmail/SendRawEmail (fallback, più lento)."""
    results = []
    try:
        ct = session.client("cloudtrail", region_name=region)
        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        for event_name in ["SendEmail", "SendRawEmail", "SendBulkEmail"]:
            try:
                paginator = ct.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    StartTime=start_time,
                    EndTime=datetime.now(timezone.utc),
                ):
                    for event in page.get("Events", []):
                        event_data = json.loads(event.get("CloudTrailEvent", "{}"))
                        req = event_data.get("requestParameters") or {}

                        source = (
                            req.get("source", "")
                            or req.get("fromEmailAddress", "")
                            or (req.get("defaultContent") or {}).get("fromEmailAddress", "")
                        )

                        subject = ""
                        msg = req.get("message") or {}
                        if isinstance(msg, dict):
                            subj_obj = msg.get("subject") or {}
                            subject = subj_obj.get("data", "") if isinstance(subj_obj, dict) else str(subj_obj)

                        match_sender = not sender_filter or sender_filter.lower() in source.lower()
                        match_subject = not subject_filter or subject_filter.lower() in subject.lower()

                        if match_sender and match_subject:
                            dest = req.get("destination") or {}
                            to_addresses = dest.get("toAddresses", []) if isinstance(dest, dict) else []
                            results.append({
                                "event_name": event_name,
                                "event_time": str(event.get("EventTime", "")),
                                "source": source,
                                "subject": subject,
                                "to": to_addresses[:5],
                                "region": region,
                                "caller": event_data.get("userIdentity", {}).get("arn", "N/A"),
                            })
            except ClientError:
                pass
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Orchestrazione per account
# ---------------------------------------------------------------------------
def search_account(master_session, account, role_name, regions, sender_filter,
                   subject_filter, days, master_account_id, use_cloudtrail):
    """Esegue la ricerca completa in un singolo account usando endpoint SES nativi."""
    account_id = account["Id"]
    result = {
        "account_id": account_id,
        "account_name": account.get("Name", account_id),
        "account_email": account.get("Email", ""),
        "ses_accounts": [],          # Info account SES per regione
        "identities": [],            # Identità verificate
        "message_insights": [],      # Export job results (VDM)
        "suppression_list": [],      # Suppression list matches
        "event_destinations": [],    # Dove vanno i log SES
        "cloudtrail_events": [],     # Solo se --cloudtrail
        "errors": [],
    }

    session = get_session_for_account(master_session, account_id, role_name, master_account_id)
    if session is None:
        result["errors"].append(f"Impossibile assumere ruolo {role_name}")
        return result

    for region in regions:
        # 1. Info account SES (quota, VDM, stato)
        account_info = get_ses_account_info(session, region)
        if account_info and account_info["sending_enabled"]:
            result["ses_accounts"].append(account_info)

            # 2. Identità verificate
            if sender_filter:
                identities = search_ses_identities(session, region, sender_filter)
                result["identities"].extend(identities)

            # 3. Message Insights via Export (solo se VDM attivo)
            if account_info.get("vdm_enabled"):
                insights, status = search_message_insights_export(
                    session, region, sender_filter, subject_filter, days
                )
                if insights:
                    result["message_insights"].extend(insights)
                elif status not in ("VDM_DISABLED", "NO_FILTER", "OK"):
                    result["errors"].append(f"Message Insights {region}: {status}")

            # 4. Suppression list
            if sender_filter:
                suppressed = search_suppression_list(session, region, sender_filter)
                result["suppression_list"].extend(suppressed)

            # 5. Configuration sets / event destinations
            event_dests = list_configuration_sets_with_events(session, region)
            result["event_destinations"].extend(event_dests)

            # 6. CloudTrail (solo se richiesto)
            if use_cloudtrail:
                ct_events = search_cloudtrail_ses_events(
                    session, region, sender_filter, subject_filter, days
                )
                result["cloudtrail_events"].extend(ct_events)

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_results(all_results, sender_filter, subject_filter, use_cloudtrail):
    """Stampa i risultati."""
    print("\n" + "=" * 80)
    print("RISULTATI RICERCA SES CROSS-ACCOUNT")
    print("=" * 80)
    if sender_filter:
        print(f"  Filtro sender:  {sender_filter}")
    if subject_filter:
        print(f"  Filtro oggetto: {subject_filter}")
    print("=" * 80)

    totals = {"accounts_ses_active": 0, "identities": 0, "insights": 0,
              "suppressed": 0, "event_dests": 0, "ct_events": 0, "accounts_with_findings": 0}

    for res in all_results:
        has_findings = any([
            res["ses_accounts"], res["identities"], res["message_insights"],
            res["suppression_list"], res["event_destinations"], res["cloudtrail_events"],
        ])
        if not has_findings and not res["errors"]:
            continue

        if has_findings:
            totals["accounts_with_findings"] += 1

        print(f"\n{'─' * 60}")
        print(f"Account: {res['account_name']} ({res['account_id']})")
        if res["account_email"]:
            print(f"Email:   {res['account_email']}")

        for err in res["errors"]:
            print(f"  [!] {err}")

        # Account SES attivi per regione
        if res["ses_accounts"]:
            totals["accounts_ses_active"] += 1
            print(f"\n  SES attivo in {len(res['ses_accounts'])} regioni:")
            for sa in res["ses_accounts"]:
                vdm = "VDM ON" if sa["vdm_enabled"] else "VDM OFF"
                prod = "PRODUCTION" if sa["production_access"] else "SANDBOX"
                print(f"    {sa['region']}: {prod} | {vdm} | "
                      f"rate={sa['max_send_rate']}/s | "
                      f"sent_24h={sa['sent_last_24h']}/{sa['max_24h']}")

        # Identità
        if res["identities"]:
            totals["identities"] += len(res["identities"])
            print(f"\n  Identita SES trovate ({len(res['identities'])}):")
            for ident in res["identities"]:
                status = "ATTIVO" if ident["sending_enabled"] else "DISATTIVO"
                print(f"    - {ident['identity']} [{ident['type']}] ({status}) [{ident['region']}]")

        # Message Insights
        if res["message_insights"]:
            totals["insights"] += sum(m.get("exported_records", 0) for m in res["message_insights"])
            print(f"\n  Message Insights (VDM export):")
            for mi in res["message_insights"]:
                print(f"    Job {mi['job_id']} [{mi['region']}]: "
                      f"{mi['exported_records']}/{mi['processed_records']} messaggi trovati")
                if mi.get("s3_url"):
                    print(f"      Download: {mi['s3_url']}")

        # Suppression list
        if res["suppression_list"]:
            totals["suppressed"] += len(res["suppression_list"])
            print(f"\n  Suppression list ({len(res['suppression_list'])}):")
            for sup in res["suppression_list"]:
                print(f"    - {sup['email']} ({sup['reason']}) [{sup['region']}] {sup['last_update']}")

        # Event destinations (dove cercare i log)
        if res["event_destinations"]:
            totals["event_dests"] += len(res["event_destinations"])
            print(f"\n  Event Destinations ({len(res['event_destinations'])}) "
                  f"- dove cercare i log di invio:")
            for ed in res["event_destinations"]:
                enabled = "ON" if ed["enabled"] else "OFF"
                extra = ""
                if ed.get("topic"):
                    extra = f" -> {ed['topic']}"
                elif ed.get("stream"):
                    extra = f" -> {ed['stream']}"
                events_str = ",".join(ed["events"][:4])
                print(f"    - {ed['config_set']}/{ed['destination_name']} "
                      f"[{ed['type']}] ({enabled}) [{ed['region']}] events=[{events_str}]{extra}")

        # CloudTrail (se attivo)
        if res["cloudtrail_events"]:
            totals["ct_events"] += len(res["cloudtrail_events"])
            print(f"\n  CloudTrail - Email inviate ({len(res['cloudtrail_events'])}):")
            for evt in res["cloudtrail_events"][:30]:
                to_str = ", ".join(evt["to"][:3]) if evt["to"] else "N/A"
                subj = (evt["subject"][:50] + "...") if len(evt["subject"]) > 50 else evt["subject"]
                print(f"    [{evt['event_time']}] {evt['event_name']}")
                print(f"      Da: {evt['source']}  A: {to_str}")
                if subj:
                    print(f"      Oggetto: {subj}")
            if len(res["cloudtrail_events"]) > 30:
                print(f"    ... e altri {len(res['cloudtrail_events']) - 30}")

    # Riepilogo
    print(f"\n{'=' * 80}")
    print("RIEPILOGO")
    print(f"{'=' * 80}")
    print(f"  Account analizzati:          {len(all_results)}")
    print(f"  Account con risultati:       {totals['accounts_with_findings']}")
    print(f"  Account con SES attivo:      {totals['accounts_ses_active']}")
    print(f"  Identita SES matchate:       {totals['identities']}")
    print(f"  Message Insights (VDM):      {totals['insights']} messaggi")
    print(f"  Suppression list matches:    {totals['suppressed']}")
    print(f"  Event destinations trovate:  {totals['event_dests']}")
    if use_cloudtrail:
        print(f"  Eventi CloudTrail:           {totals['ct_events']}")
    print(f"{'=' * 80}")


def export_json(all_results, output_file):
    """Esporta in JSON."""
    filtered = [r for r in all_results if any([
        r["ses_accounts"], r["identities"], r["message_insights"],
        r["suppression_list"], r["event_destinations"], r["cloudtrail_events"], r["errors"],
    ])]
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nRisultati esportati in: {output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Cerca email SES in tutti gli account AWS (usa endpoint SES nativi)"
    )
    parser.add_argument("--sender", "-s", default="",
                        help="Filtro sender (email o dominio, match parziale)")
    parser.add_argument("--subject", "-S", default="",
                        help="Filtro oggetto (match parziale, richiede VDM)")
    parser.add_argument("--role-name", "-r", default="OrganizationAccountAccessRole",
                        help="Ruolo da assumere (default: OrganizationAccountAccessRole)")
    parser.add_argument("--days", "-d", type=int, default=7,
                        help="Giorni indietro per Message Insights/CloudTrail (default: 7, max VDM: 30)")
    parser.add_argument("--regions", default="",
                        help="Regioni da analizzare (virgola-separate, default: tutte)")
    parser.add_argument("--output", "-o", default="",
                        help="File JSON di output")
    parser.add_argument("--threads", "-t", type=int, default=5,
                        help="Thread paralleli (default: 5)")
    parser.add_argument("--profile", "-p", default=None,
                        help="AWS CLI profile")
    parser.add_argument("--account-ids", default="",
                        help="Solo questi account (virgola-separati)")
    parser.add_argument("--cloudtrail", action="store_true",
                        help="Attiva anche ricerca CloudTrail (piu lento ma non richiede VDM)")

    args = parser.parse_args()

    if not args.sender and not args.subject:
        parser.error("Specificare almeno --sender o --subject")

    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else ALL_SES_REGIONS
    days = min(max(args.days, 1), 90)

    print("=" * 80)
    print("SES SEARCH - Ricerca cross-account (endpoint SES nativi)")
    print("=" * 80)
    if args.sender:
        print(f"  Sender:      {args.sender}")
    if args.subject:
        print(f"  Oggetto:     {args.subject}")
    print(f"  Ruolo:       {args.role_name}")
    print(f"  Giorni:      {days}")
    print(f"  Regioni:     {len(regions)}")
    print(f"  CloudTrail:  {'SI' if args.cloudtrail else 'NO (usa --cloudtrail per attivare)'}")

    # Session master
    try:
        session_kwargs = {"profile_name": args.profile} if args.profile else {}
        master_session = boto3.Session(**session_kwargs)
        sts = master_session.client("sts")
        identity = sts.get_caller_identity()
        master_account_id = identity["Account"]
        print(f"\n  Master Account: {master_account_id}")
        print(f"  Caller ARN:     {identity['Arn']}")
    except NoCredentialsError:
        print("\n[ERRORE] Credenziali AWS non configurate.")
        sys.exit(1)
    except ClientError as e:
        print(f"\n[ERRORE] {e}")
        sys.exit(1)

    # Account list
    if args.account_ids:
        account_ids = [a.strip() for a in args.account_ids.split(",") if a.strip()]
        accounts = [{"Id": aid, "Name": aid, "Email": ""} for aid in account_ids]
    else:
        print("\n  Recupero account dall'organizzazione...")
        try:
            accounts = get_org_accounts(master_session)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
                print(f"  [!] {code} - uso solo account corrente")
                accounts = [{"Id": master_account_id, "Name": "Current", "Email": ""}]
            else:
                print(f"  [ERRORE] {e}")
                sys.exit(1)
    print(f"  Account da analizzare: {len(accounts)}")

    # Ricerca parallela
    print(f"\n  Avvio ricerca...\n")
    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for account in accounts:
            future = executor.submit(
                search_account, master_session, account, args.role_name, regions,
                args.sender, args.subject, days, master_account_id, args.cloudtrail,
            )
            futures[future] = account

        for i, future in enumerate(as_completed(futures), 1):
            account = futures[future]
            try:
                result = future.result()
                all_results.append(result)
                n = (len(result["identities"]) + len(result["message_insights"])
                     + len(result["cloudtrail_events"]) + len(result["suppression_list"]))
                status = f"{n} risultati" if n else "nessun match"
                ses_active = len(result["ses_accounts"])
                print(f"  [{i}/{len(accounts)}] {account.get('Name', account['Id'])} "
                      f"- SES attivo in {ses_active} regioni - {status}")
            except Exception as e:
                print(f"  [{i}/{len(accounts)}] {account.get('Name', account['Id'])} - ERRORE: {e}")

    print_results(all_results, args.sender, args.subject, args.cloudtrail)

    if args.output:
        export_json(all_results, args.output)


if __name__ == "__main__":
    main()
