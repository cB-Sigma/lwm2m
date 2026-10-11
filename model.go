package lwm2m

import "strconv"

// Resource data types of the LwM2M object model.
const (
	tString   = "string"
	tInteger  = "integer"
	tUnsigned = "unsigned"
	tFloat    = "float"
	tBool     = "boolean"
	tOpaque   = "opaque"
	tTime     = "time"
	tObjlnk   = "objlnk"
	tCorelnk  = "corelnk" // CoRE link format text (LwM2M 1.1 appendix C)
	tExec     = "execute"
)

// ResourceDef is what is known about one resource: a short name for
// labels, its type (for TLV, which carries no types) and a unit.
type ResourceDef struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty" ipeschema:"required"`
	Unit string `json:"unit,omitempty"`
}

// The built-in model covers the objects most devices serve: Device
// (3), Connectivity Monitoring (4) and Temperature (3303, IPSO), plus the
// objects bootstrap and device management use: Security (0), Server (1),
// Firmware Update (5) and Software Management (9). Names and
// types are those of the OMA LwM2M registry entries, written as short
// identifiers; units are UCUM codes.
var objectNames = map[int]string{0: "security", 1: "server", 3: "device", 4: "connectivity", 5: "firmware", 9: "software", 21: "oscore", 25: "gateway", 26: "gateway-routing", 3303: "temperature"}

var model = map[int]map[int]ResourceDef{
	0: {
		0: {"server-uri", tString, ""}, 1: {"bootstrap-server", tBool, ""}, 2: {"security-mode", tInteger, ""},
		3: {"public-key-or-identity", tOpaque, ""}, 4: {"server-public-key", tOpaque, ""}, 5: {"secret-key", tOpaque, ""},
		10: {"short-server-id", tInteger, ""}, 11: {"client-hold-off-time", tInteger, "s"},
		// LwM2M 1.1 and 1.2 additions (object version 1.2)
		6: {"sms-security-mode", tInteger, ""}, 7: {"sms-binding-key-parameters", tOpaque, ""},
		8: {"sms-binding-secret-keys", tOpaque, ""}, 9: {"server-sms-number", tString, ""},
		12: {"bootstrap-server-account-timeout", tInteger, "s"}, 13: {"matching-type", tUnsigned, ""},
		14: {"sni", tString, ""}, 15: {"certificate-usage", tUnsigned, ""}, 16: {"dtls-tls-ciphersuite", tUnsigned, ""},
		17: {"oscore-security-mode", tObjlnk, ""}, 18: {"groups-to-use-by-client", tUnsigned, ""},
		19: {"signature-algorithms-supported-by-server", tUnsigned, ""}, 20: {"signature-algorithms-to-use-by-client", tUnsigned, ""},
		21: {"signature-algorithm-certs-supported-by-server", tUnsigned, ""}, 22: {"tls13-features-to-use-by-client", tUnsigned, ""},
		23: {"tls-extensions-supported-by-server", tUnsigned, ""}, 24: {"tls-extensions-to-use-by-client", tUnsigned, ""},
		25: {"secondary-server-uri", tString, ""}, 26: {"mqtt-server", tObjlnk, ""}, 27: {"cose-security", tObjlnk, ""},
		28: {"rds-destination-port", tInteger, ""}, 29: {"rds-source-port", tInteger, ""}, 30: {"rds-application-id", tString, ""},
	},
	1: {
		0: {"short-server-id", tInteger, ""}, 1: {"lifetime", tInteger, "s"}, 2: {"default-minimum-period", tInteger, "s"},
		3: {"default-maximum-period", tInteger, "s"}, 4: {"disable", tExec, ""}, 5: {"disable-timeout", tInteger, "s"},
		6: {"notification-storing", tBool, ""}, 7: {"binding", tString, ""},
		8: {"registration-update-trigger", tExec, ""}, 9: {"bootstrap-request-trigger", tExec, ""},
		// LwM2M 1.1 and 1.2 additions (object version 1.2)
		10: {"apn-link", tObjlnk, ""}, 11: {"tls-dtls-alert-code", tUnsigned, ""}, 12: {"last-bootstrapped", tTime, ""},
		13: {"registration-priority-order", tUnsigned, ""}, 14: {"initial-registration-delay-timer", tUnsigned, "s"},
		15: {"registration-failure-block", tBool, ""}, 16: {"bootstrap-on-registration-failure", tBool, ""},
		17: {"communication-retry-count", tUnsigned, ""}, 18: {"communication-retry-timer", tUnsigned, "s"},
		19: {"communication-sequence-delay-timer", tUnsigned, "s"}, 20: {"communication-sequence-retry-count", tUnsigned, ""},
		21: {"trigger", tBool, ""}, 22: {"preferred-transport", tString, ""}, 23: {"mute-send", tBool, ""},
		24: {"alternate-apn-links", tObjlnk, ""}, 25: {"supported-server-versions", tString, ""},
		26: {"default-notification-mode", tInteger, ""}, 27: {"profile-id-hash-algorithm", tUnsigned, ""},
	},
	5: {
		0: {"package", tOpaque, ""}, 1: {"package-uri", tString, ""}, 2: {"update", tExec, ""}, 3: {"state", tInteger, ""},
		5: {"update-result", tInteger, ""}, 6: {"pkg-name", tString, ""}, 7: {"pkg-version", tString, ""},
		8: {"firmware-update-protocol-support", tInteger, ""}, 9: {"firmware-update-delivery-method", tInteger, ""},
		// LwM2M 1.2 firmware update enhancements (object version 1.2)
		10: {"cancel", tExec, ""}, 11: {"severity", tInteger, ""}, 12: {"last-state-change-time", tTime, ""},
		13: {"maximum-defer-period", tUnsigned, "s"}, 14: {"automatic-upgrade-at-download", tBool, ""},
	},
	9: {
		0: {"pkg-name", tString, ""}, 1: {"pkg-version", tString, ""}, 2: {"package", tOpaque, ""}, 3: {"package-uri", tString, ""},
		4: {"install", tExec, ""}, 6: {"uninstall", tExec, ""}, 7: {"update-state", tInteger, ""},
		8: {"update-supported-objects", tBool, ""}, 9: {"update-result", tInteger, ""}, 10: {"activate", tExec, ""},
		11: {"deactivate", tExec, ""}, 12: {"activation-state", tBool, ""}, 14: {"user-name", tString, ""}, 15: {"password", tString, ""},
	},
	3: {
		0: {"manufacturer", tString, ""}, 1: {"model-number", tString, ""}, 2: {"serial-number", tString, ""},
		3: {"firmware-version", tString, ""}, 4: {"reboot", tExec, ""}, 5: {"factory-reset", tExec, ""},
		6: {"available-power-sources", tInteger, ""}, 7: {"power-source-voltage", tInteger, "mV"},
		8: {"power-source-current", tInteger, "mA"}, 9: {"battery-level", tInteger, "%"},
		10: {"memory-free", tInteger, "KiBy"}, 11: {"error-code", tInteger, ""}, 12: {"reset-error-code", tExec, ""},
		13: {"current-time", tTime, ""}, 14: {"utc-offset", tString, ""}, 15: {"timezone", tString, ""},
		16: {"supported-binding-modes", tString, ""}, 17: {"device-type", tString, ""},
		18: {"hardware-version", tString, ""}, 19: {"software-version", tString, ""},
		20: {"battery-status", tInteger, ""}, 21: {"memory-total", tInteger, "KiBy"}, 22: {"ext-dev-info", tObjlnk, ""},
	},
	4: {
		0: {"network-bearer", tInteger, ""}, 1: {"available-network-bearer", tInteger, ""},
		2: {"radio-signal-strength", tInteger, "dBm"}, 3: {"link-quality", tInteger, ""},
		4: {"ip-addresses", tString, ""}, 5: {"router-ip-addresses", tString, ""},
		6: {"link-utilization", tInteger, "%"}, 7: {"apn", tString, ""}, 8: {"cell-id", tInteger, ""},
		9: {"smnc", tInteger, ""}, 10: {"smcc", tInteger, ""},
	},
	// LwM2M 1.2 core objects (registry XMLs 21, 25 and 26): OSCORE,
	// LwM2M Gateway (object version 2.0) and LwM2M Gateway Routing.
	21: {
		0: {"master-secret", tOpaque, ""}, 1: {"sender-id", tOpaque, ""}, 2: {"recipient-id", tOpaque, ""},
		3: {"aead-algorithm", tInteger, ""}, 4: {"hmac-algorithm", tInteger, ""}, 5: {"master-salt", tOpaque, ""},
		6: {"id-context", tOpaque, ""},
	},
	25: {0: {"device-id", tString, ""}, 1: {"prefix", tString, ""}, 3: {"iot-device-objects", tCorelnk, ""}},
	26: {0: {"object-id", tUnsigned, ""}, 1: {"mapping-info", tCorelnk, ""}},
	3303: {
		5700: {"sensor-value", tFloat, "Cel"}, 5701: {"sensor-units", tString, ""},
		5601: {"min-measured-value", tFloat, "Cel"}, 5602: {"max-measured-value", tFloat, "Cel"},
		5603: {"min-range-value", tFloat, "Cel"}, 5604: {"max-range-value", tFloat, "Cel"},
		5605: {"reset-min-max", tExec, ""}, 5750: {"application-type", tString, ""},
	},
}

// Model is the built-in object model plus the resources an application
// defines ("/<object>/<resource>" → definition). A nil Model is the
// built-in one.
type Model map[string]ResourceDef

// Lookup returns what is known about the resource at p.
func (m Model) Lookup(p Path) ResourceDef {
	if d, ok := m["/"+strconv.Itoa(p.Obj)+"/"+strconv.Itoa(p.Res)]; ok {
		return d
	}
	return model[p.Obj][p.Res]
}

// pointName is the data point (container) name of a resource: its path
// with '-' separators, "3303-0-5700". Paths keep names stable across
// clients and objects the model does not know.
func pointName(p Path) string {
	s := strconv.Itoa(p.Obj) + "-" + strconv.Itoa(p.Inst) + "-" + strconv.Itoa(p.Res)
	if p.RI >= 0 {
		s += "-" + strconv.Itoa(p.RI)
	}
	return s
}
