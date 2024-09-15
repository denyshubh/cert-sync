package controllers

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsclient "github.com/denyshubh/cert-sync/pkg/aws"
)

// SecretReconciler reconciles a Secret Object
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// Reconcile is part of the main kubernetes reconciliation loop

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)
	log.Info("Reconciling Secret")

	// Initialize AWS ACM Client
	acmClient, err := awsclient.NewACMClient(ctx)
	if err != nil {
		log.Error(err, "Failed to initialize AWS ACM Client")
		return ctrl.Result{}, err
	}

	// Fetch the Secret Instance
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if errors.IsNotFound(err) {
			// Secret not found
			return ctrl.Result{}, nil
		}
		// Error reading the object
		return ctrl.Result{}, err
	}

	// Check if the secret has a sync annotation
	if secret.Annotations["sync-to-acm"] != "true" {
		log.Info("Secret does not have sync-to-acm annotations; skipping")
		return ctrl.Result{}, nil
	}

	// Check if Secret is of type TLS
	if secret.Type != corev1.SecretTypeTLS {
		log.Info("Secret is not of type kubernetes.io/tls; skipping")
		return ctrl.Result{}, nil
	}

	// Get the domain name from the annotation
	domainName, exists := secret.Annotations["cert-manager.io/common-name"]
	if !exists || domainName == "" {
		log.Info("Secret does not have cert-manager.io/common-name annotation; skipping")
		return ctrl.Result{}, nil
	}

	// Find existing certificate in ACM
	existingCertificate, err := r.findSecretByDomain(ctx, acmClient, domainName)
	if err != nil {
		log.Error(err, "Error finding certificate in ACM")
		return ctrl.Result{}, err
	}

	// Extract the certificate and key
	cert := secret.Data[corev1.TLSCertKey]
	key := secret.Data[corev1.TLSPrivateKeyKey]

	if existingCertificate != nil {
		log.Info("Found certificate in ACM", "CertificateArn: ", *existingCertificate.CertificateArn, "NotAfter: ", *existingCertificate.NotAfter)
		if existingCertificate.NotAfter != nil && existingCertificate.NotAfter.Before(time.Now()) {
			log.Info("Certificate exists in ACM and is expired; updating certificate")

			// Process to sync (import) the certificate

			if err := r.updateToAcm(ctx, acmClient, &secret, *existingCertificate.CertificateArn, cert, key); err != nil {
				log.Error(err, "Failed to sync certificate to ACM")
				return ctrl.Result{}, err
			}

		} else {
			log.Info("Certificate exists in ACM and is valid; skipping import")
		}
	} else {
		log.Info("Certificate does not exist in ACM; importing certificate")

		// Sync to ACM
		if err := r.importToAcm(ctx, acmClient, &secret, cert, key); err != nil {
			log.Error(err, "Failed to sync certificate to ACM")
			return ctrl.Result{}, err
		}
	}

	log.Info("Sucessfully synced certificate to ACM")
	return ctrl.Result{}, nil
}

func (r *SecretReconciler) importToAcm(ctx context.Context, acmClient *acm.Client, secret *corev1.Secret, certPEM, keyPEM []byte) error {

	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/acm#ImportCertificateInput
	input := &acm.ImportCertificateInput{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		Tags: []types.Tag{
			{
				Key:   aws.String("kubernetes-secrets"),
				Value: aws.String(secret.Namespace + "/" + secret.Name),
			},
		},
	}

	// Import the certificate
	_, err := acmClient.ImportCertificate(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

func (r *SecretReconciler) updateToAcm(ctx context.Context, acmClient *acm.Client, secret *corev1.Secret, certificateArn string, certPEM, keyPEM []byte) error {

	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/acm#ImportCertificateInput
	input := &acm.ImportCertificateInput{
		Certificate:    certPEM,
		PrivateKey:     keyPEM,
		CertificateArn: &certificateArn,
		Tags: []types.Tag{
			{
				Key:   aws.String("kubernetes-secrets"),
				Value: aws.String(secret.Namespace + "/" + secret.Name),
			},
		},
	}

	// Import the certificate
	_, err := acmClient.ImportCertificate(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

func (r *SecretReconciler) findSecretByDomain(ctx context.Context, acmClient *acm.Client, domainName string) (*types.CertificateDetail, error) {
	// use ListCertificates with a filter on a domain name
	input := &acm.ListCertificatesInput{
		CertificateStatuses: []types.CertificateStatus{
			types.CertificateStatusIssued,
			types.CertificateStatusInactive,
			types.CertificateStatusExpired,
			types.CertificateStatusRevoked,
		},
		Includes: &types.Filters{
			ExtendedKeyUsage: []types.ExtendedKeyUsageName{
				types.ExtendedKeyUsageNameTlsWebClientAuthentication,
				types.ExtendedKeyUsageNameTlsWebServerAuthentication,
			},
		},
	}

	paginator := acm.NewListCertificatesPaginator(acmClient, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, certSummary := range page.CertificateSummaryList {
			certDetailInput := &acm.DescribeCertificateInput{
				CertificateArn: certSummary.CertificateArn,
			}

			certDetailOutput, err := acmClient.DescribeCertificate(ctx, certDetailInput)
			if err != nil {
				return nil, err
			}

			certDetail := certDetailOutput.Certificate
			if certDetail.DomainName == &domainName {
				return certDetail, nil
			}

			// Also check Subject Alternative Names
			for _, san := range certDetail.SubjectAlternativeNames {
				if san == domainName {
					return certDetail, nil
				}
			}
		}
	}
	// certificate not found
	return nil, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}
