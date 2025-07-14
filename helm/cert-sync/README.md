# cert-sync Helm Chart

A Helm chart for deploying the cert-sync controller that syncs certificates from AWS ACM to Kubernetes secrets.

## Installation

1. Install the chart with default values:
```bash
helm install cert-sync ./helm/cert-sync
```

2. Install with custom AWS IAM role ARN:
```bash
helm install cert-sync ./helm/cert-sync \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::123456789012:role/eks-acm-controller"
```

3. Install with custom image version:
```bash
helm install cert-sync ./helm/cert-sync \
  --set image.tag=v1.0.0
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `denyshubh/cert-sync-controller` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Service account annotations | `eks.amazonaws.com/role-arn: arn:aws:iam::<AWS_ACCOUNT_ID>:role/eks-acm-controller` |
| `namespace.create` | Create namespace | `true` |
| `namespace.name` | Namespace name | `cert-sync-system` |
| `rbac.create` | Create RBAC resources | `true` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |

## Upgrading

To upgrade the chart:
```bash
helm upgrade cert-sync ./helm/cert-sync
```

## Uninstalling

To uninstall the chart:
```bash
helm uninstall cert-sync
```

## Values File Example

Create a `values.yaml` file for custom configuration:

```yaml
image:
  repository: denyshubh/cert-sync-controller
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/eks-acm-controller

resources:
  limits:
    cpu: 1000m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

nodeSelector:
  kubernetes.io/os: linux
```

Then install with:
```bash
helm install cert-sync ./helm/cert-sync -f values.yaml
``` 