# METADATA
# title: CC6.7 - DMS Redis In-Transit Encryption
# description: DMS endpoints using Redis should have in-transit encryption enabled
# scope: package
package sigcomply.soc2.cc6_7_dms_redis_encryption

metadata := {
	"id": "soc2-cc6.7-dms-redis-encryption",
	"name": "DMS Redis In-Transit Encryption",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dms:endpoint"],
	"remediation": "Enable SSL/TLS encryption on the DMS Redis endpoint.",
}

violations contains violation if {
	input.resource_type == "aws:dms:endpoint"
	input.data.engine_name == "redis"
	input.data.ssl_mode == "none"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "DMS Redis endpoint does not have in-transit encryption enabled",
		"details": {"engine_name": input.data.engine_name, "ssl_mode": input.data.ssl_mode},
	}
}
