#!/usr/bin/env python3
"""
find_ses_account.py - Trova l'account AWS che ha inviato un'email tramite SES.

================================================================================
COSA FA
================================================================================

Dato il Message-ID di un'email inviata tramite Amazon SES, identifica quale
account AWS dell'organizzazione l'ha inviata. Lo fa cercando in CloudTrail
di ogni account il campo responseElements.messageId degli eventi SendEmail.

Il Message-ID SES ha questo formato:
    <0100018f1a2b3c4d-abcdef01-2345-6789-abcd-ef0123456789-000000@eu-west-1.amazonses.com>

Da cui lo script estrae automaticamente:
    - Regione SES: eu-west-1 (dalla parte dopo la @)
    - SES Message-ID: 0100018f1a2b3c4d-abcdef01-... (la parte prima della @)

================================================================================
DOVE TROVARE IL MESSAGE-ID
================================================================================

Il Message-ID si trova negli header dell'email ricevuta. Per visualizzarli:

    Gmail:
        Apri l'email > menu (3 puntini) > "Mostra originale"
        Cerca la riga "Message-ID:" oppure "X-SES-Outgoing"

    Outlook:
        Apri l'email > File > Proprieta > "Intestazioni Internet"

    Thunderbird:
        Apri l'email > Visualizza > Sorgente del messaggio (Ctrl+U)

    Apple Mail:
        Apri l'email > Visualizza > Messaggio > Sorgente completa

    Header da cercare (in ordine di preferenza):
        Message-ID: <xxx@eu-west-1.amazonses.com>    <-- questo!
        X-SES-MESSAGE-ID: 0100018f1a2b3c4d-xxx        <-- anche questo va bene

================================================================================
PREREQUISITI
================================================================================

1. Python 3.7+

2. Installare boto3:
       pip install boto3

3. Credenziali AWS del MASTER ACCOUNT (management account) dell'organizzazione.
   Configurale con uno di questi metodi:
       - aws configure                       (credenziali nel profilo default)
       - aws configure --profile mio-master  (profilo dedicato, poi usa --profile)
       - Variabili d'ambiente AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
       - IAM role su EC2/Lambda (automatico)

4. Un ruolo IAM assumibile in ogni account membro. Di default lo script usa
   "OrganizationAccountAccessRole" che AWS crea automaticamente quando aggiungi
   un account all'organizzazione. Se usi un ruolo diverso, passa --role-name.

5. Il ruolo deve avere almeno queste permission:
       - cloudtrail:LookupEvents
       - sts:AssumeRole (sul master account)
       - organizations:ListAccounts (sul master account)

================================================================================
USO
================================================================================

    Uso base (passa il Message-ID completo con la regione):

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com"

    Con profilo AWS specifico:

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com" --profile prod-master

    Con ruolo custom:

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com" --role-name AdminAccessRole

    Cercare piu' indietro nel tempo (default 14 giorni, max 90):

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com" --days 30

    Cercare solo in account specifici (se sai gia' i candidati):

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com" --account-ids 111122223333,444455556666

    Aumentare il parallelismo (default 10 thread):

        python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com" --threads 20

================================================================================
PARAMETRI
================================================================================

    message_id              (obbligatorio) Il Message-ID dell'email SES.
                            Accetta sia il formato completo con < > sia senza.

    --role-name, -r         Nome del ruolo da assumere negli account.
                            Default: OrganizationAccountAccessRole

    --profile, -p           Nome del profilo AWS CLI da usare.

    --days, -d              Quanti giorni indietro cercare in CloudTrail.
                            Default: 14. Max: 90 (limite CloudTrail).

    --threads, -t           Numero di thread per la ricerca parallela.
                            Default: 10.

    --account-ids           Lista di account ID separati da virgola.
                            Se specificato, cerca solo in questi account
                            invece che in tutta l'organizzazione.

================================================================================
COME FUNZIONA
================================================================================

    1. Parsing del Message-ID
       Estrae la regione SES (es: eu-west-1) e l'ID del messaggio.

    2. Lista account
       Chiama organizations:ListAccounts per ottenere tutti gli account attivi
       dell'organizzazione (oppure usa --account-ids).

    3. Ricerca parallela
       Per ogni account, in parallelo:
       - Assume il ruolo nell'account (sts:AssumeRole)
       - Chiama cloudtrail:LookupEvents nella regione estratta
       - Cerca eventi SendEmail/SendRawEmail/SendBulkEmail/SendTemplatedEmail
       - Confronta responseElements.messageId con il Message-ID cercato

    4. Primo match = stop
       Appena trova il match si ferma e stampa tutti i dettagli:
       Account ID, nome, caller ARN, timestamp, from, to, subject, IP, ecc.

================================================================================
OUTPUT DI ESEMPIO
================================================================================

    $ python find_ses_account.py "0100018f-xxxx@eu-west-1.amazonses.com"

      SES Message-ID: 0100018f-xxxx
      Regione:        eu-west-1
      Master Account: 000000000000
      Account da cercare: 15
      Ultimi 14 giorni

      Ricerca in corso...

      [ ] Account-Dev (111111111111)
      [ ] Account-Staging (222222222222)
      [*] Account-Prod (333333333333) - *** TROVATO ***

    ======================================================================
      TROVATO!
    ======================================================================
      Account ID:    333333333333
      Account Name:  Account-Prod
      Regione:       eu-west-1
      Evento:        SendEmail
      Timestamp:     2024-01-15 10:30:45+00:00
      Message-ID:    0100018f-xxxx
      From:          noreply@example.com
      To:            destinatario@gmail.com
      Subject:       Conferma ordine #12345
      Source IP:     10.0.1.50
      Caller ARN:    arn:aws:iam::333333333333:role/MyAppRole
      Caller Type:   AssumedRole
      User Agent:    aws-sdk-python/1.26.0
    ======================================================================

================================================================================
TROUBLESHOOTING
================================================================================

    "NON TROVATO"
        - L'email e' stata inviata piu' di --days giorni fa? Prova --days 90
        - Il Message-ID e' corretto? Deve contenere @region.amazonses.com
        - CloudTrail potrebbe non essere attivo in tutti gli account
        - Il ruolo potrebbe non esistere in alcuni account

    "Regione non trovata nel Message-ID"
        - Il Message-ID deve contenere @region.amazonses.com
        - Se hai solo l'X-SES-MESSAGE-ID (senza @), aggiungi la regione:
          "0100018f-xxxx@eu-west-1.amazonses.com"

    "skip (no role access)"
        - Il ruolo non esiste in quell'account, o non hai permesso di assumerlo
        - Verifica con: aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/RUOLO

    Lo script e' lento
        - Aumenta i thread: --threads 20
        - Riduci i giorni: --days 7
        - Specifica gli account candidati: --account-ids 111,222,333
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError


def parse_message_id(raw):
    """Estrae regione e SES message ID dal Message-ID."""
    raw = raw.strip().strip("<>")

    # Estrae regione da xxx@region.amazonses.com
    m = re.search(r"@([a-z0-9-]+)\.amazonses\.com", raw)
    region = m.group(1) if m else None

    # L'ID SES è la parte prima della @
    ses_id = raw.split("@")[0] if "@" in raw else raw

    return ses_id, region


def get_org_accounts(session):
    org = session.client("organizations")
    accounts = []
    for page in org.get_paginator("list_accounts").paginate():
        for a in page["Accounts"]:
            if a["Status"] == "ACTIVE":
                accounts.append(a)
    return accounts


def assume_role(master_session, account_id, role_name):
    try:
        resp = master_session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="SESFind",
        )
        c = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=c["AccessKeyId"],
            aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"],
        )
    except ClientError:
        return None


def search_cloudtrail(session, region, ses_id, days):
    """Cerca in CloudTrail eventi SES il cui responseElements.messageId matcha."""
    ct = session.client("cloudtrail", region_name=region)
    start = datetime.now(timezone.utc) - timedelta(days=days)
    end = datetime.now(timezone.utc)

    for event_name in ["SendEmail", "SendRawEmail", "SendBulkEmail",
                       "SendTemplatedEmail", "SendBulkTemplatedEmail"]:
        try:
            for page in ct.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start, EndTime=end,
            ):
                for event in page.get("Events", []):
                    ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                    resp_msg_id = (ct_event.get("responseElements") or {}).get("messageId", "")

                    if ses_id in resp_msg_id or resp_msg_id in ses_id:
                        req = ct_event.get("requestParameters") or {}
                        user = ct_event.get("userIdentity") or {}
                        dest = req.get("destination") or {}
                        to = dest.get("toAddresses", []) if isinstance(dest, dict) else []

                        subject = ""
                        msg = req.get("message") or {}
                        if isinstance(msg, dict):
                            s = msg.get("subject") or {}
                            subject = s.get("data", "") if isinstance(s, dict) else str(s)

                        return {
                            "event": event_name,
                            "time": str(event.get("EventTime", "")),
                            "message_id": resp_msg_id,
                            "from": req.get("source", "") or req.get("fromEmailAddress", ""),
                            "to": to,
                            "subject": subject,
                            "region": region,
                            "source_ip": ct_event.get("sourceIPAddress", ""),
                            "caller_arn": user.get("arn", ""),
                            "caller_type": user.get("type", ""),
                            "account_id": ct_event.get("recipientAccountId", user.get("accountId", "")),
                            "user_agent": ct_event.get("userAgent", ""),
                        }
        except ClientError:
            pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Trova l'account AWS che ha inviato un'email SES")
    parser.add_argument("message_id", help="Il Message-ID dell'email (es: xxx@eu-west-1.amazonses.com)")
    parser.add_argument("--role-name", "-r", default="OrganizationAccountAccessRole")
    parser.add_argument("--profile", "-p", default=None)
    parser.add_argument("--days", "-d", type=int, default=14, help="Giorni indietro (default: 14)")
    parser.add_argument("--threads", "-t", type=int, default=10)
    parser.add_argument("--account-ids", default="", help="Cerca solo in questi account")
    args = parser.parse_args()

    ses_id, region = parse_message_id(args.message_id)

    print(f"\n  SES Message-ID: {ses_id}")
    if region:
        print(f"  Regione:        {region}")
    else:
        print("  [!] Regione non trovata nel Message-ID. Servira' cercare in tutte le regioni.")
        print("  [!] Suggerimento: passa il Message-ID completo (xxx@region.amazonses.com)")
        sys.exit(1)

    # Session
    kw = {"profile_name": args.profile} if args.profile else {}
    master_session = boto3.Session(**kw)
    sts = master_session.client("sts")
    master_account_id = sts.get_caller_identity()["Account"]
    print(f"  Master Account: {master_account_id}")

    # Account list
    if args.account_ids:
        ids = [a.strip() for a in args.account_ids.split(",") if a.strip()]
        accounts = [{"Id": i, "Name": i} for i in ids]
    else:
        try:
            accounts = get_org_accounts(master_session)
        except ClientError:
            accounts = [{"Id": master_account_id, "Name": "Current"}]

    print(f"  Account da cercare: {len(accounts)}")
    print(f"  Ultimi {args.days} giorni")
    print(f"\n  Ricerca in corso...\n")

    # Ricerca parallela - si ferma al primo match
    found = None
    found_account = None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for account in accounts:
            aid = account["Id"]
            if aid == master_account_id:
                session = master_session
            else:
                session = assume_role(master_session, aid, args.role_name)
                if session is None:
                    print(f"  [ ] {account.get('Name', aid)} ({aid}) - skip (no role access)")
                    continue

            future = executor.submit(search_cloudtrail, session, region, ses_id, args.days)
            futures[future] = account

        for future in as_completed(futures):
            account = futures[future]
            aid = account["Id"]
            try:
                result = future.result()
                if result:
                    print(f"  [*] {account.get('Name', aid)} ({aid}) - *** TROVATO ***")
                    found = result
                    found_account = account
                    # Cancella i futures rimanenti
                    for f in futures:
                        f.cancel()
                    break
                else:
                    print(f"  [ ] {account.get('Name', aid)} ({aid})")
            except Exception as e:
                print(f"  [!] {account.get('Name', aid)} ({aid}) - errore: {e}")

    # Risultato
    print(f"\n{'=' * 70}")
    if found:
        print(f"  TROVATO!")
        print(f"{'=' * 70}")
        print(f"  Account ID:    {found['account_id']}")
        print(f"  Account Name:  {found_account.get('Name', '')}")
        print(f"  Regione:       {found['region']}")
        print(f"  Evento:        {found['event']}")
        print(f"  Timestamp:     {found['time']}")
        print(f"  Message-ID:    {found['message_id']}")
        print(f"  From:          {found['from']}")
        print(f"  To:            {', '.join(found['to'][:5])}")
        if found["subject"]:
            print(f"  Subject:       {found['subject']}")
        print(f"  Source IP:     {found['source_ip']}")
        print(f"  Caller ARN:   {found['caller_arn']}")
        print(f"  Caller Type:  {found['caller_type']}")
        print(f"  User Agent:   {found['user_agent']}")
    else:
        print(f"  NON TROVATO")
        print(f"{'=' * 70}")
        print(f"  Possibili cause:")
        print(f"  - Evento piu' vecchio di {args.days} giorni (prova --days 90)")
        print(f"  - Il ruolo '{args.role_name}' non esiste in alcuni account")
        print(f"  - CloudTrail non attivo o non ha registrato l'evento")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
