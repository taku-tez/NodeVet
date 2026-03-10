package rules

// All returns all registered NV1xxx rules.
func All() []Rule {
	all := []Rule{
		// Authentication / Authorization (NV1001–NV1004)
		ruleAnonymousAuth,
		ruleAuthorizationMode,
		ruleClientCAFile,
		ruleReadOnlyPort,
		// TLS (NV1101–NV1105)
		ruleTLSCertFile,
		ruleTLSPrivateKeyFile,
		ruleTLSCipherSuites,
		ruleRotateCertificates,
		ruleRotateServerCertificates,
		// Pod / Container control (NV1201–NV1204)
		ruleProtectKernelDefaults,
		ruleMakeIPTablesUtilChains,
		ruleEventQPS,
		ruleStreamingConnectionIdleTimeout,
	}
	// Back-fill Rule pointer on each Finding via the Check wrapper.
	// We wrap each Check function so that Finding.Rule is always populated.
	for i := range all {
		r := &all[i]
		originalCheck := r.Check
		r.Check = func(values map[string]string) *Finding {
			f := originalCheck(values)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
