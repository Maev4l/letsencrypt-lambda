# Let's Encrypt Lambda

Renew / request certificate from Let's Encrypt CA

## Renew / Request a certificate

Based on a configuration file: config.json

Can be invoked manually via renew-\* npm scripts

## Revoke certificate

```
npx sls invoke --function revokeCertificate --data='{"arn":<certificate arn>"}'
```

## Issued certificates status

see: https://tools.letsdebug.net/cert-search
