# find_ses_account.py

Trova quale account AWS ha inviato un'email tramite SES, dato il Message-ID.

Lo script cerca in CloudTrail di ogni account dell'organizzazione il match
sul `responseElements.messageId` degli eventi SendEmail.

**Lo script e' 100% di sola lettura. Non crea, modifica o cancella nulla in AWS.**

---

## Dove trovare il Message-ID

Il Message-ID si trova negli header dell'email ricevuta:

| Client | Come fare |
|--------|-----------|
| Gmail | Apri email > 3 puntini > "Mostra originale" |
| Outlook | Apri email > File > Proprieta > "Intestazioni Internet" |
| Thunderbird | Visualizza > Sorgente del messaggio (Ctrl+U) |
| Apple Mail | Visualizza > Messaggio > Sorgente completa |

Cerca la riga:
```
Message-ID: <0100018f1a2b3c4d-xxxxx@eu-west-1.amazonses.com>
```

La parte dopo `@` e' la regione SES (es: `eu-west-1`).

---

## Prerequisiti

### 1. Python 3.7+

```bash
python --version
```

Se non c'e': scaricalo da python.org oppure `winget install Python.Python.3`

### 2. Installa dipendenze

```bash
pip install -r requirements.txt
```

### 3. AWS CLI

```bash
winget install Amazon.AWSCLI
aws --version
```

### 4. Configura credenziali del master account

Con SSO:
```bash
aws configure sso
```

Con Access Key:
```bash
aws configure --profile master
```

### 5. Verifica che funzioni

```bash
aws sts get-caller-identity --profile TUO_PROFILO
```

Deve restituire l'Account ID del master account.

---

## Setup del ruolo cross-account (StackSet)

Lo script ha bisogno di un ruolo in ogni account membro per accedere a CloudTrail.
Se l'organizzazione ha gia' `OrganizationAccountAccessRole`, salta questa sezione.
Altrimenti (es: usi SSO e non hai ruoli cross-account), segui questa procedura
per creare un ruolo temporaneo read-only in tutti gli account.

### Step 1 - Trova il tuo Master Account ID

```bash
aws sts get-caller-identity --profile TUO_PROFILO --query 'Account' --output text
```

Copia il numero di 12 cifre.

### Step 2 - Attiva trusted access per CloudFormation StackSets

Dalla console AWS:
1. Vai su **CloudFormation** > **StackSets**
2. Se vedi un banner "Enable trusted access" > cliccalo
3. Se non c'e' nessun banner, e' gia' attivo

### Step 3 - Crea lo StackSet

```bash
aws cloudformation create-stack-set \
  --stack-set-name SESFinderRole \
  --template-body file://ses-finder-role.yaml \
  --parameters ParameterKey=MasterAccountId,ParameterValue=IL_TUO_MASTER_ACCOUNT_ID \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile TUO_PROFILO
```

Sostituisci `IL_TUO_MASTER_ACCOUNT_ID` con il numero dello Step 1.

### Step 4 - Deploya in tutti gli account

Trova l'ID della root OU:

```bash
aws organizations list-roots --profile TUO_PROFILO --query 'Roots[0].Id' --output text
```

Copia l'ID (formato `r-xxxx`). Poi deploya:

```bash
aws cloudformation create-stack-instances \
  --stack-set-name SESFinderRole \
  --deployment-targets OrganizationalUnitIds='["r-XXXX"]' \
  --regions '["eu-west-1"]' \
  --profile TUO_PROFILO
```

Sostituisci `r-XXXX` con il tuo root ID.

### Step 5 - Verifica che il deploy sia completato (~2-5 minuti)

```bash
aws cloudformation list-stack-set-operations \
  --stack-set-name SESFinderRole \
  --profile TUO_PROFILO \
  --query 'Summaries[0].Status'
```

Quando dice `SUCCEEDED`, vai avanti.

---

## Lancia lo script

Se hai creato il ruolo con lo StackSet:

```bash
python find_ses_account.py "MSG-ID@eu-west-1.amazonses.com" --profile TUO_PROFILO --role-name SESFinderReadOnly
```

Se usi `OrganizationAccountAccessRole` (default):

```bash
python find_ses_account.py "MSG-ID@eu-west-1.amazonses.com" --profile TUO_PROFILO
```

### Parametri

| Parametro | Descrizione | Default |
|-----------|-------------|---------|
| `message_id` | Message-ID dell'email (obbligatorio) | - |
| `--profile`, `-p` | AWS CLI profile | default |
| `--role-name`, `-r` | Nome del ruolo cross-account | OrganizationAccountAccessRole |
| `--days`, `-d` | Giorni indietro in CloudTrail | 14 (max 90) |
| `--threads`, `-t` | Thread paralleli | 10 |
| `--account-ids` | Solo questi account (virgola-separati) | tutti |

### Output atteso

```
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
  From:          noreply@example.com
  To:            destinatario@gmail.com
  Subject:       Conferma ordine #12345
  Caller ARN:    arn:aws:iam::333333333333:role/MyAppRole
======================================================================
```

### Troubleshooting

| Problema | Soluzione |
|----------|-----------|
| "NON TROVATO" | Prova `--days 90` per cercare piu' indietro |
| "skip (no role access)" su tutti | Il ruolo non esiste. Segui la sezione StackSet sopra |
| "skip (no role access)" su alcuni | Normale per account invitati. Se gli altri funzionano, ok |
| "security token not valid" | Token SSO scaduto. Rinnova con `aws sso login --profile TUO_PROFILO` |
| "Regione non trovata" | Il Message-ID deve contenere `@regione.amazonses.com` |

---

## Pulizia: rimuovi il ruolo da tutti gli account

Dopo aver trovato l'account, rimuovi tutto.

### Step 1 - Cancella le istanze (rimuove il ruolo da tutti gli account)

```bash
aws cloudformation delete-stack-instances \
  --stack-set-name SESFinderRole \
  --deployment-targets OrganizationalUnitIds='["r-XXXX"]' \
  --regions '["eu-west-1"]' \
  --no-retain-stacks \
  --profile TUO_PROFILO
```

Sostituisci `r-XXXX` con lo stesso root ID usato nel deploy.

### Step 2 - Attendi completamento (~2-5 minuti)

```bash
aws cloudformation list-stack-set-operations \
  --stack-set-name SESFinderRole \
  --profile TUO_PROFILO \
  --query 'Summaries[0].Status'
```

Quando dice `SUCCEEDED`, prosegui.

### Step 3 - Cancella lo StackSet

```bash
aws cloudformation delete-stack-set \
  --stack-set-name SESFinderRole \
  --profile TUO_PROFILO
```

Fatto. Il ruolo `SESFinderReadOnly` e' stato rimosso da tutti gli account
e lo StackSet e' stato eliminato. Non resta nulla.

---

## Riepilogo processo completo

| # | Cosa | Comando | Tempo |
|---|------|---------|-------|
| 1 | Trova master account ID | `aws sts get-caller-identity` | 10 sec |
| 2 | Attiva trusted access | Console > CloudFormation > StackSets | 1 min |
| 3 | Crea StackSet | `aws cloudformation create-stack-set ...` | 10 sec |
| 4 | Deploya ruolo | `aws cloudformation create-stack-instances ...` | 2-5 min |
| 5 | **Lancia script** | `python find_ses_account.py "MSG-ID" ...` | **1-2 min** |
| 6 | Rimuovi istanze | `aws cloudformation delete-stack-instances ...` | 2-5 min |
| 7 | Cancella StackSet | `aws cloudformation delete-stack-set ...` | 10 sec |
