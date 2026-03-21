# METADATA
# title: CC6.6 - Open Database Ports
# description: Security groups must not allow 0.0.0.0/0 on high-risk database ports (3306, 5432, 1433, 6379, 27017)
# scope: package
package sigcomply.soc2.cc6_6_open_db_ports

metadata := {
	"id": "soc2-cc6.6-open-db-ports",
	"name": "Open Database Ports",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:security-group"],
	"remediation": "Restrict database ports (3306, 5432, 1433, 6379, 27017) access to specific IP ranges or security groups. Never allow 0.0.0.0/0.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_mysql == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows MySQL (port 3306) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 3306,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_postgres == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows PostgreSQL (port 5432) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 5432,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_mssql == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows MSSQL (port 1433) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 1433,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_redis == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows Redis (port 6379) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 6379,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_mongodb == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows MongoDB (port 27017) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 27017,
		},
	}
}
