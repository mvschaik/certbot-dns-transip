# Script for DNS-01 auth hook for Transip

This is a simple python script to help creating and cleaning up a TXT
record for validating a domain using DNS-01 using certbot. It can be
used for `--manual-auth-hook` and `--manual-cleanup-hook`.

It is designed to not have any dependencies, it should work with any recent version
of python3.

Example usage:

auth-transip.sh
```
certbot-dns-transip.py \
    create $CERTBOT_DOMAIN \
    --username=<my username> \
    --private_keyfile=<private.key> \
    --validation="$CERTBOT_VALIDATION"
```

cleanup-transip.sh
```
TOKEN=$(echo $CERTBOT_AUTH_OUTPUT | awk '/JWT:/{print $2}')
certbot-dns-transip.py \
    cleanup $CERTBOT_DOMAIN \
    --bearer_token="$TOKEN"
```

Certbot command
```
certbot certonly --manual --preferred_challenges=dns \
    --manual-auth-hook=auth-transip.sh \
    --manual-cleanup-hook=cleanup-transip.sh \
    --domain=some.domain.com
```

