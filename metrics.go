package main

import (
	"crypto/x509"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	helpSSLEarliestCertExpiry     = "Returns last SSL chain expiry in unixtime"
	helpSSLChainExpiryInTimeStamp = "Returns last SSL chain expiry in timestamp"
	helpProbeSSLLastInformation   = "Contains SSL leaf certificate information"
)

var (
	sslEarliestCertExpiryGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: helpSSLEarliestCertExpiry,
	}

	sslChainExpiryInTimeStampGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_expiry_timestamp_seconds",
		Help: helpSSLChainExpiryInTimeStamp,
	}

	probeSSLLastInformationGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_info",
		Help: helpProbeSSLLastInformation,
	}
)

func metrics(cert *x509.Certificate) *prometheus.Registry {
	registry := prometheus.NewRegistry()

	probeSSLEarliestCertExpiryGauge := prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
	probeSSLLastChainExpiryTimestampSeconds := prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)

	probeSSLLastInformation := prometheus.NewGaugeVec(probeSSLLastInformationGaugeOpts,
		[]string{"subject", "issuer", "subjectdnsnames", "serialnumber"},
	)

	registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)

	probeSSLEarliestCertExpiryGauge.Set(float64(cert.NotAfter.Unix()))
	probeSSLLastChainExpiryTimestampSeconds.Set(float64(cert.NotAfter.Unix()))
	probeSSLLastInformation.WithLabelValues(cert.Subject.String(), cert.Issuer.CommonName, strings.Join(cert.DNSNames, ","),
		cert.SerialNumber.String(),
	).Set(1)

	return registry
}
