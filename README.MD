Preparazione step by step

  1. Python

  Verifica di avere Python 3.7+:
  python --version
  Se non ce l'hai: scaricalo da python.org oppure winget install Python.Python.3

  2. Installa dipendenze

  cd "C:\Users\jodya\OneDrive\Documents\_CODE\_Projects\amazon_read"
  pip install -r requirements.txt

  Oppure semplicemente:
  pip install boto3

  3. AWS CLI (se non ce l'hai)

  winget install Amazon.AWSCLI

  Poi verifica:
  aws --version

  4. Configura le credenziali del master account

  Hai bisogno delle credenziali di un utente IAM (o ruolo) nel management account dell'organizzazione.

  aws configure --profile master

  Ti chiederà:
  AWS Access Key ID:      AKIA...........
  AWS Secret Access Key:  wJal...........
  Default region:         eu-west-1
  Default output format:  json

  5. Verifica che funzioni

  aws sts get-caller-identity --profile master

  Deve restituire qualcosa tipo:
  {
      "UserId": "AIDA...",
      "Account": "000000000000",    <-- questo deve essere il master account
      "Arn": "arn:aws:iam::000000000000:user/tuonome"
  }

  6. Verifica i permessi

  L'utente/ruolo che usi deve avere queste permission:

  sts:GetCallerIdentity          (ce l'hanno tutti di default)
  organizations:ListAccounts     (per listare gli account dell'org)
  sts:AssumeRole                 (per entrare negli account membri)

  E il ruolo target negli account membri (OrganizationAccountAccessRole di default) deve avere:

  cloudtrail:LookupEvents        (per cercare gli eventi)

  OrganizationAccountAccessRole ha AdministratorAccess, quindi ha tutto. Se usate un ruolo custom verifica che abbia
  almeno cloudtrail:LookupEvents.

  7. Lancia

  python find_ses_account.py "IL-TUO-MESSAGE-ID@eu-west-1.amazonses.com" --profile master

  ---
  Checklist rapida

  ┌───────────────────────┬──────────────────────────────────────────────────┬──────────────────────────────────────┐
  │         Step          │                     Comando                      │                 OK?                  │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ Python installato     │ python --version                                 │ 3.7+                                 │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ boto3 installato      │ pip install boto3                                │                                      │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ AWS CLI installato    │ aws --version                                    │                                      │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ Credenziali           │ aws configure --profile master                   │                                      │
  │ configurate           │                                                  │                                      │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ Sei nel master        │ aws sts get-caller-identity --profile master     │                                      │
  │ account               │                                                  │                                      │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ Hai il Message-ID     │ dagli header dell'email                          │ deve finire con                      │
  │                       │                                                  │ @regione.amazonses.com               │
  ├───────────────────────┼──────────────────────────────────────────────────┼──────────────────────────────────────┤
  │ Lancia                │ python find_ses_account.py "MSG-ID" --profile    │                                      │
  │                       │ master                                           │                                      │
  └───────────────────────┴──────────────────────────────────────────────────┴──────────────────────────────────────┘