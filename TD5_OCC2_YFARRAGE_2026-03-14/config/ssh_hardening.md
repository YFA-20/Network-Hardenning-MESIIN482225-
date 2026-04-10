# SSH Hardening — siteB-srv (AWS)

## Approach

`siteB-srv` is an AWS EC2 instance running Ubuntu 22.04 (cloud image). The AWS cloud AMI pre-configures `PasswordAuthentication no` in `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf`. TD5 hardening was applied via a dedicated drop-in file to avoid modifying vendor-managed config.

## Files modified

| File | Action |
|------|--------|
| `/etc/ssh/sshd_config.d/99-td5-hardening.conf` | Created — contains all TD5 hardening directives |
| `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf` | Untouched — `PasswordAuthentication no` already set |

## `/etc/ssh/sshd_config.d/99-td5-hardening.conf`

```
PermitRootLogin no
AllowUsers awsuser
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
```

## Effective sshd configuration (combined)

| Directive | Source | Value |
|-----------|--------|-------|
| `PasswordAuthentication` | 60-cloudimg-settings.conf | `no` |
| `PermitRootLogin` | 99-td5-hardening.conf | `no` |
| `AllowUsers` | 99-td5-hardening.conf | `awsuser` |
| `PubkeyAuthentication` | 99-td5-hardening.conf | `yes` |
| `MaxAuthTries` | 99-td5-hardening.conf | `3` |
| `LoginGraceTime` | 99-td5-hardening.conf | `30` |

## Admin user

The AWS default user `awsuser` acts as the sole authorised admin. SSH key: ED25519, fingerprint `SHA256:TJd0H81dkHZCDKn//p8lGWRnsbNRv/dsDkMBlo7mQg4`. Key deployed via AWS EC2 key pair at instance launch.

## Pre-change key test

Before applying the hardening config, the key login was verified:
```bash
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 whoami
# Output: awsuser
```
This ensures the key is functional before disabling password fallback (prevents lockout).

## Service restart sequence

```bash
sudo sshd -t                    # syntax check
sudo systemctl restart ssh      # reload daemon
```
