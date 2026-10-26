<!-- Temporary: comment for issue #2. Post it, then delete this file (and the drafts/ folder).
     gh issue comment 2 --repo viktormar1337/ipsec-tunnelmatch --body-file drafts/issue-2-comment.md -->
### AWS and Google Cloud are in, help wanted with testing

Added in 3101679 and live on the site:

- **AWS Site-to-Site VPN**: AWS CLI script or Terraform (hashicorp/aws 6.x). Customer gateway plus a static-route VPN connection with both tunnels configured the same way. Works with a virtual private gateway (`vgw-…`) or a transit gateway (`tgw-…`).
- **Google Cloud VPN**: Classic VPN with static routing (HA VPN needs BGP, which the tool doesn't generate), as a gcloud script or Terraform (hashicorp/google 8.x) with the tunnel cipher suite and a write-only shared secret.

The supported algorithms, lifetime limits, required PFS and the one-SA-pair-per-tunnel rule come from AWS's and Google's current docs. The generated Terraform passes `terraform validate`, but **none of it has run against a real AWS or GCP account yet**.

**If you have an AWS account or a GCP project you can test with**, this would help a lot:

1. Generate a config with the cloud on one side and your own device (or strongSwan) on the other.
2. Deploy it with the script or with Terraform.
3. Report back here: did both tunnels (AWS) or the tunnel (GCP) come up, what was negotiated, and what did you have to change? Or use **Report a working configuration** in the tool.

Never post pre-shared keys, account or project IDs, or real public IPs.
