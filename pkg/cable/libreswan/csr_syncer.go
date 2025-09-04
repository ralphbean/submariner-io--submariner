/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package libreswan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/syncer"
	"github.com/submariner-io/admiral/pkg/syncer/broker"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	RSABitSize        = 2048
	CertLabelKey      = "submariner.io/csr-request"
	PrivateKeyDataKey = "tls.key"
	CSRDataKey        = "csr.pem"
	SignedCertDataKey = "tls.crt"
)

var csrLogger = log.Logger{Logger: logf.Log.WithName("certificate-csr-syncer")}

func getCertSecretName(clusterID string) string {
	return fmt.Sprintf("submariner-certificate-%s", clusterID)
}

func (i *libreswan) EnsureCertificateSecret(clusterID string, sanIPs []string) error {
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")
	secretClient := i.syncerConfig.LocalClient.Resource(gvr).Namespace(i.syncerConfig.LocalNamespace)

	certSecretName := getCertSecretName(clusterID)
	_, err := secretClient.Get(context.TODO(), certSecretName, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	if !errors.IsNotFound(err) {
		return err
	}

	keyPEM, csrPEM, err := generateKeyAndCSR(clusterID, sanIPs)
	if err != nil {
		return fmt.Errorf("failed to generate key and CSR: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certSecretName,
			Namespace: i.syncerConfig.LocalNamespace,
			Labels: map[string]string{
				CertLabelKey: clusterID,
			},
		},
		Data: map[string][]byte{
			PrivateKeyDataKey: keyPEM,
			CSRDataKey:        csrPEM,
		},
	}

	unstructuredSecret := &unstructured.Unstructured{}
	err = i.syncerConfig.Scheme.Convert(secret, unstructuredSecret, nil)
	if err != nil {
		return fmt.Errorf("failed to convert Secret to unstructured: %w", err)
	}

	_, err = secretClient.Create(context.TODO(), unstructuredSecret, metav1.CreateOptions{})
	return err
}

func (i *libreswan) DeleteCertificateSecret(ctx context.Context, clusterID string) error {
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")

	certSecretName := getCertSecretName(clusterID)
	err := i.syncerConfig.LocalClient.Resource(gvr).
		Namespace(i.syncerConfig.LocalNamespace).
		Delete(ctx, certSecretName, metav1.DeleteOptions{})

	return err
}
func generateKeyAndCSR(clusterID string, sanIPs []string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSABitSize)
	if err != nil {
		return nil, nil, err
	}

	ipAddresses := []net.IP{}
	for _, ip := range sanIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, nil, fmt.Errorf("invalid IP address in SAN: %s", ip)
		}
		ipAddresses = append(ipAddresses, parsed)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("submariner-%s", clusterID),
			Organization: []string{"submariner.io"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return keyPEM, csrPEM, nil
}

func SetupCertificateSecretSyncer(syncerConfig broker.SyncerConfig) (*broker.Syncer, error) {

	// Default broker namespace if not provided
	if syncerConfig.BrokerNamespace == "" {
		syncerConfig.BrokerNamespace = "submariner-k8s-broker"
		csrLogger.Infof("CSR syncer: defaulting brokerNamespace=%s", syncerConfig.BrokerNamespace)
	}

	localCID := syncerConfig.LocalClusterID
	syncerConfig.LocalClusterID = ""

	csrLogger.Infof("CSR syncer configured: localNamespace=%s clusterID=%s brokerNamespace=%s",
		syncerConfig.LocalNamespace, localCID, syncerConfig.BrokerNamespace)

	syncerConfig.ResourceConfigs = []broker.ResourceConfig{
		{

			LocalSourceNamespace: syncerConfig.LocalNamespace,
			LocalResourceType:    &corev1.Secret{},
			TransformLocalToBroker: func(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
				secret := from.(*corev1.Secret)

				if secret.Labels[CertLabelKey] != localCID {
					csrLogger.V(1).Infof("local->broker skip %s/%s: %s=%q want %q",
						secret.Namespace, secret.Name, CertLabelKey, secret.Labels[CertLabelKey], localCID)
					return nil, false
				}

				// Copy and strip private key
				newSecret := secret.DeepCopy()
				delete(newSecret.Data, PrivateKeyDataKey)

				csrLogger.V(1).Infof("local->broker sync %s/%s", newSecret.Namespace, newSecret.Name)
				return newSecret, true
			},
			BrokerResourceType: &corev1.Secret{},
			TransformBrokerToLocal: func(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
				secret := from.(*corev1.Secret)

				_, hasCrt := secret.Data[SignedCertDataKey]
				_, hasCA := secret.Data["ca.crt"]
				_, hasSigned := secret.Annotations["submariner.io/csr-request-signed"]
				csrLogger.V(1).Infof("broker->local inspect %s/%s: %s=%q signedAnno=%t tls.crt=%t ca.crt=%t",
					secret.Namespace, secret.Name, CertLabelKey, secret.Labels[CertLabelKey], hasSigned, hasCrt, hasCA)

				if secret.Labels[CertLabelKey] != localCID {
					csrLogger.Infof("broker->local skip %s/%s: %s=%q want %q",
						secret.Namespace, secret.Name, CertLabelKey, secret.Labels[CertLabelKey], localCID)
					return nil, false
				}

				if _, ok := secret.Annotations["submariner.io/csr-request-signed"]; !ok {
					csrLogger.Infof("broker->local skip %s/%s: annotation submariner.io/csr-request-signed missing",
						secret.Namespace, secret.Name)
					return nil, false
				}

				if _, ok := secret.Data[SignedCertDataKey]; !ok {
					csrLogger.Infof("broker->local skip %s/%s: %s missing",
						secret.Namespace, secret.Name, SignedCertDataKey)
					return nil, false
				}

				gvr := corev1.SchemeGroupVersion.WithResource("secrets")

				existingUnstructured, err := syncerConfig.LocalClient.Resource(gvr).
					Namespace(syncerConfig.LocalNamespace).
					Get(context.TODO(), secret.Name, metav1.GetOptions{})
				if err == nil {
					existingSecret := &corev1.Secret{}
					if err := syncerConfig.Scheme.Convert(existingUnstructured, existingSecret, nil); err == nil {
						if key, ok := existingSecret.Data[PrivateKeyDataKey]; ok {
							if secret.Data == nil {
								secret.Data = map[string][]byte{}
							}
							secret.Data[PrivateKeyDataKey] = key
						}
					}
				}

				csrLogger.Infof("broker->local sync %s/%s -> %s (preserving key if present)",
					secret.Namespace, secret.Name, syncerConfig.LocalNamespace)

				return secret, true
			},
		},
	}
	return broker.NewSyncer(syncerConfig)
}
