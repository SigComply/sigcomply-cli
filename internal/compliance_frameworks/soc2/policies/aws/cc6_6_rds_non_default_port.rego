# METADATA
# title: CC6.6 - RDS Non-Default Port
# description: RDS instances should not use default database engine ports
# scope: package
package sigcomply.soc2.cc6_6_rds_non_default_port

metadata := {
	"id": "soc2-cc6.6-rds-non-default-port",
	"name": "RDS Non-Default Port",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "When creating RDS instances, specify a non-default port to reduce exposure to automated scanning attacks.",
}

default_ports := {
	"mysql": 3306,
	"mariadb": 3306,
	"postgres": 5432,
	"oracle-ee": 1521,
	"oracle-se2": 1521,
	"sqlserver-ee": 1433,
	"sqlserver-se": 1433,
	"sqlserver-ex": 1433,
	"sqlserver-web": 1433,
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	engine := input.data.engine
	default_port := default_ports[engine]
	input.data.port == default_port
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' uses default port %d for engine '%s'", [input.data.db_instance_id, default_port, engine]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": engine,
			"port": input.data.port,
		},
	}
}
