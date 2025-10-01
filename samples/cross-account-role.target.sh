# Create trust policy allowing the controller role to assume this role
cat > target-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<REDACTED_SOURCE_ACCOUNT_ID>:role/eks-acm-controller"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create the role in target account
aws iam create-role \
  --role-name cert-sync-target-role \
  --assume-role-policy-document file://target-trust-policy.json \
  --description "Role for cert-sync to import certificates to ACM"

# Attach ACM permissions policy
cat > acm-permissions.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:ImportCertificate",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:AddTagsToCertificate"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name cert-sync-target-role \
  --policy-name ACMImportPermissions \
  --policy-document file://acm-permissions.json