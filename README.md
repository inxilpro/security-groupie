# Security Groupie

**[⬇ Download the latest release](https://github.com/inxilpro/security-groupie/releases/latest)**
(macOS 15.4 or later)

Security Groupie is a menu bar app that keeps an AWS security group rule
pointed at your current public IP. When your network changes, it checks your
IP and, if it moved, updates the rule for this Mac so you can keep reaching
your servers over SSH (or any port) without editing the security group by
hand.

## How it works

Each Mac gets one inbound rule in the security group, identified by its
device name (the rule's description). When the IP changes, Security Groupie
updates that rule in place, or creates it if it doesn't exist yet. If another
rule already allows your IP on that port, it leaves the group alone.

Your public IP comes from `checkip.amazonaws.com`, with `api.ipify.org` as a
fallback. You get a notification whenever the rule is created or updated.

## Setup

Open **Settings…** from the menu bar icon and fill in:

- **Authentication**: IAM Identity Center (SSO) is recommended. Enter your
  start URL and SSO region, sign in through the browser, then pick an account
  and role. Tokens are kept in your Keychain; `~/.aws` isn't used. An access
  key and secret also work.
- **Region** and **Security Group**: both become pickers once you're
  connected.
- **Port**: 22 by default.
- **Device Name**: defaults to your Mac's name.

When an SSO session expires and your IP changes, Security Groupie notifies you
to sign in again, then applies the pending update.

### IAM permissions

The role or user needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:ModifySecurityGroupRules"
      ],
      "Resource": "*"
    }
  ]
}
```

Scope `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules` to the
security group's ARN if you want to limit what the app can change.

## Updates

Security Groupie updates itself with [Sparkle](https://sparkle-project.org).
It checks automatically (turn this off in Settings → Updates), and **Check for
Updates…** in the menu bar menu checks on demand. Updates come from this
repository's GitHub releases and are verified against a signing key built into
the app.

## Building

Open `Security Groupie.xcodeproj` in Xcode 27 and run the **Security Groupie**
scheme. Releases are built by GitHub Actions when a `vX.Y.Z` tag is pushed; see
[Documentation/RELEASING.md](Documentation/RELEASING.md).
