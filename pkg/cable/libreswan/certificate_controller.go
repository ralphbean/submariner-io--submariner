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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/watcher"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var certLogger = log.Logger{Logger: logf.Log.WithName("certificate-controller")}

// CertificateController watches certificate secrets and loads them into NSS database
type CertificateController struct {
	client         dynamic.Interface
	restConfig     *rest.Config
	clusterID      string
	localNameSpace string
	nssDBDir       string
	stopCh         chan struct{}
	watcher        watcher.Interface
	lastCertHash   string
}

func NewCertificateController(client dynamic.Interface, restConfig *rest.Config, localNameSpace, clusterID string) *CertificateController {
	return &CertificateController{
		client:         client,
		restConfig:     restConfig,
		clusterID:      clusterID,
		localNameSpace: localNameSpace,
		nssDBDir:       "/var/lib/ipsec/nss",
		stopCh:         make(chan struct{}),
	}
}

func (c *CertificateController) Start() error {
	certSecretName := getCertSecretName(c.clusterID)
	certLogger.Info("Starting certificate controller", "secretName", certSecretName, "namespace", c.localNameSpace)

	config := watcher.Config{
		ResourceConfigs: []watcher.ResourceConfig{
			{
				Name:         "Certificate Secret watcher",
				ResourceType: &corev1.Secret{},
				Handler: watcher.EventHandlerFuncs{
					OnCreateFunc: c.handleSecret,
					OnUpdateFunc: c.handleSecret,
					OnDeleteFunc: func(runtime.Object, int) bool { c.cleanupCertificateFromNSS(); return false },
				},
				SourceNamespace: c.localNameSpace,
			},
		},
	}
	config.RestConfig = c.restConfig

	var err error
	c.watcher, err = watcher.New(&config)
	if err != nil {
		return err
	}

	go c.watcher.Start(c.stopCh)
	certLogger.Info("Certificate controller started successfully (watcher mode)")
	return nil
}

func (c *CertificateController) Stop() {
	certLogger.Info("Stopping certificate controller")
	c.cleanupCertificateFromNSS()
	close(c.stopCh)
}

func (c *CertificateController) cleanupCertificateFromNSS() {
	certName := fmt.Sprintf("submariner-client-%s", c.clusterID)
	caName := "submariner-ca"
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	// Delete client certificate
	cmd := exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", certName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		certLogger.Warningf("Failed to delete client certificate from NSS database: %v, output: %s", err, string(output))
	} else {
		certLogger.Infof("Deleted Submariner client certificate from NSS database: %s", certName)
	}

	// Delete CA certificate
	cmd = exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", caName)
	output, err = cmd.CombinedOutput()
	if err != nil {
		certLogger.Warningf("Failed to delete CA certificate from NSS database: %v, output: %s", err, string(output))
	} else {
		certLogger.Infof("Deleted Submariner CA certificate from NSS database: %s", caName)
	}
}

func (c *CertificateController) handleSecret(obj runtime.Object, _ int) bool {
	secret := obj.(*corev1.Secret)

	if secret.Name != getCertSecretName(c.clusterID) {
		return false
	}

	// Check if certificate is signed
	annotations := secret.Annotations
	if annotations == nil {
		certLogger.V(log.TRACE).Info("No annotations found, certificate not yet signed")
		return false
	}
	signedAnnotation := annotations["submariner.io/csr-request-signed"]
	if signedAnnotation != "true" {
		certLogger.Info("Certificate not yet signed, skipping NSS loading")
		return false
	}

	// Extract certificate data (base64 encoded)
	tlsCertB64, tlsOk := secret.Data["tls.crt"]
	tlsKeyB64, keyOk := secret.Data["tls.key"]
	caCertB64, caOk := secret.Data["ca.crt"]
	if !tlsOk || !keyOk || !caOk {
		certLogger.Info("Certificate data incomplete, skipping NSS loading")
		return false
	}

	// Compute hash of cert+key+ca
	certData := string(tlsCertB64) + string(tlsKeyB64) + string(caCertB64)
	certHash := fmt.Sprintf("%x", sha256.Sum256([]byte(certData)))
	if certHash == c.lastCertHash {
		log.V(1).Info("Certificate data unchanged, skipping NSS loading")
		return false
	}

	// Decode base64 data (already decoded in secret.Data)
	tlsCert := tlsCertB64
	tlsKey := tlsKeyB64
	caCert := caCertB64

	certLogger.Info("Certificate ready, loading into NSS database")
	c.logCertificateDetails(tlsCert)
	if err := c.initNSSDatabase(); err != nil {
		certLogger.Error(err, "Failed to initialize NSS database")
		return false
	}
	if err := c.loadCertificatesIntoNSS(tlsCert, tlsKey, caCert); err != nil {
		certLogger.Error(err, "Failed to load certificates into NSS database")
		return false
	}
	certLogger.Info("Certificates successfully loaded into NSS database")
	c.lastCertHash = certHash
	return false
}

func (c *CertificateController) initNSSDatabase() error {
	if _, err := os.Stat(c.nssDBDir + "/cert9.db"); err == nil {
		certLogger.Info("NSS database already exists , using existing database")
		return nil
	}

	certLogger.Info("NSS database does not exist, initializing new database")
	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-N", "-d", "sql:"+c.nssDBDir, "--empty-password")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to initialize NSS database: %s", string(output))
	}

	certLogger.Info("NSS database initialized successfully")
	return nil
}

func (c *CertificateController) loadCertificatesIntoNSS(tlsCert, tlsKey, caCert []byte) error {
	// Load CA certificate
	if err := c.loadCACertIntoNSS(caCert); err != nil {
		return errors.Wrap(err, "failed to load CA certificate into NSS")
	}

	// Load client certificate and key
	if err := c.loadClientCertIntoNSS(tlsCert, tlsKey); err != nil {
		return errors.Wrap(err, "failed to load client certificate into NSS")
	}

	return nil
}

func (c *CertificateController) loadCACertIntoNSS(caCertPEM []byte) error {
	caName := "submariner-ca"

	// Always delete the CA cert if present
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", caName).Run()

	certLogger.Info("Loading Submariner CA certificate into NSS database")

	// Write CA cert to temporary file
	caCertFile, err := os.CreateTemp("", "submariner-ca-*.crt")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary CA cert file")
	}
	defer os.Remove(caCertFile.Name())

	if _, err := caCertFile.Write(caCertPEM); err != nil {
		return errors.Wrap(err, "failed to write CA certificate to temporary file")
	}
	caCertFile.Close()

	// Import CA certificate
	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-A", "-d", "sql:"+c.nssDBDir, "-n", caName, "-t", "CT,", "-i", caCertFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to import CA certificate: %s", string(output))
	}

	certLogger.Info("Submariner CA certificate imported successfully into NSS database")
	return nil
}

func (c *CertificateController) deleteCertAndKeyFromNSS(certName string) {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", certName).Run()
	_ = exec.CommandContext(ctx, "certutil", "-F", "-d", "sql:"+c.nssDBDir, "-k", certName).Run()
}

func (c *CertificateController) loadClientCertIntoNSS(certPEM, keyPEM []byte) error {
	certName := fmt.Sprintf("submariner-client-%s", c.clusterID)

	// Always delete the client cert and its private key if present
	c.deleteCertAndKeyFromNSS(certName)

	certLogger.Infof("Loading Submariner client certificate and key into NSS database: %s", certName)

	// Write cert and key to temp files
	certFile, err := os.CreateTemp("", "submariner-cert-*.crt")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary cert file")
	}
	defer os.Remove(certFile.Name())
	if _, err := certFile.Write(certPEM); err != nil {
		return errors.Wrap(err, "failed to write certificate to temporary file")
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "submariner-key-*.key")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary key file")
	}
	defer os.Remove(keyFile.Name())
	if _, err := keyFile.Write(keyPEM); err != nil {
		return errors.Wrap(err, "failed to write key to temporary file")
	}
	keyFile.Close()

	// Create PKCS#12 file with openssl
	p12File, err := os.CreateTemp("", "submariner-client-*.p12")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary pkcs12 file")
	}
	defer os.Remove(p12File.Name())
	p12File.Close()

	// Use a fixed password for pkcs12 (can be empty string, but libreswan doesn't care)
	pkcs12Password := ""

	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", certFile.Name(),
		"-inkey", keyFile.Name(),
		"-out", p12File.Name(),
		"-name", certName,
		"-passout", "pass:"+pkcs12Password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to create PKCS#12 file: %s", string(output))
	}

	// Import PKCS#12 into NSS
	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "pk12util", "-i", p12File.Name(), "-d", "sql:"+c.nssDBDir, "-W", pkcs12Password)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to import PKCS#12 into NSS: %s", string(output))
	}

	certLogger.Infof("Submariner client certificate and key imported successfully into NSS database: %s", certName)
	return nil
}

func (c *CertificateController) listCertificatesInNSS() error {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+c.nssDBDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to list certificates in NSS database: %s", string(output))
	}

	certLogger.Infof("All certificates in NSS database:\n%s", string(output))
	return nil
}

func (c *CertificateController) logCertificateDetails(certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		certLogger.Error(nil, "Failed to decode certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		certLogger.Error(err, "Failed to parse certificate")
		return
	}

	certLogger.Infof("Certificate Details: Subject=%s, Serial=%s", cert.Subject.String(), cert.SerialNumber.String())
	certLogger.Infof("Certificate Validity: NotBefore=%s, NotAfter=%s", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))

	if len(cert.IPAddresses) > 0 {
		ipAddrs := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipAddrs[i] = ip.String()
		}
		certLogger.Infof("Certificate Subject Alternative Names (IP addresses): %v", ipAddrs)
	}

	if len(cert.DNSNames) > 0 {
		certLogger.Infof("Certificate Subject Alternative Names (DNS names): %v", cert.DNSNames)
	}

	if len(cert.IPAddresses) == 0 && len(cert.DNSNames) == 0 {
		certLogger.Info("Certificate has no Subject Alternative Names")
	}
}
