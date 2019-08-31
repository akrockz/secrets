1. Automated way to stash and retrieve secrets
  1a. [abc-Automation] RDS never reveals the password to the user
  1b. [abc-Automation] Generate me a password and Store it in SM, retrieve it programmatically.
  1c. [Core-Iam] Restrict roles and policy for Secrets Manager to be based on portfolio and app tags.
2. A Manual way to store and retrieve secrets if I don't have a core-automation access or I have an edge case
  2a. [sia-secrets] have a python script or similar that allows me to get a secret
  2b. [Documentation] ensure that all users understand how to store, get and retrieve a secret via cron or cfn-init, etc. 


- create a secret 'fish', create a value 'cat'
- store my secret in SM in my account [nonprod-auto,prod-auto]
- then inject my secret into my application config file automatically


cron for 30 days (Database Connectivity)
-> get my secrets new value
-> mysql (connectivity/JDBC/etc NOT application user) to update my RDS instance (This could be a lambda) (NEVER USE ROOT)
-> pipe/sed/whatever to my config file
-> Restart my application (if it requires a restart)
-> Future Proof -> Enable your application to have a new password for Db connectivity without a restart. 

cron for 30 days (Application Password)
-> get my secrets new value
-> have a script to update the mysql table/call the application binary/etc with new value passed in
