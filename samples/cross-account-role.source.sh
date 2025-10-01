# Create trust policy for EKS service account (IRSA)
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<REDACTED_SOURCE_ACCOUNT_ID>:oidc-provider/oidc.eks.<REDACTED_REGION>.amazonaws.com/id/<REDACTED_OIDC_ID>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.<REDACTED_REGION>.amazonaws.com/id/<REDACTED_OIDC_ID>:sub": "system:serviceaccount:cert-sync-system:cert-sync-controller-manager",
          "oidc.eks.<REDACTED_REGION>.amazonaws.com/id/<REDACTED_OIDC_ID>:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name eks-acm-controller \
  --assume-role-policy-document file://trust-policy.json \
  --description "Role for cert-sync controller to assume cross-account roles"

# Attach policy to allow assuming roles in other accounts
cat > assume-role-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<REDACTED_TARGET_ACCOUNT_ID>:role/cert-sync-target-role"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name eks-acm-controller \
  --policy-name AssumeTargetAccountRole \
  --policy-document file://assume-role-policy.json