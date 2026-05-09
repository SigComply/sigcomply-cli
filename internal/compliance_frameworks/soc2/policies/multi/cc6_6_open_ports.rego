# METADATA
# title: CC6.6 - Open Admin Ports
# description: Security groups and firewall rules must not allow 0.0.0.0/0 on SSH(22)/RDP(3389)
# scope: package
package sigcomply.soc2.cc6_6_open_ports

metadata := {
	"id": "soc2-cc6.6-open-ports",
	"name": "Open Admin Ports",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:security-group", "gcp:compute:firewall"],
	"remediation": "Restrict SSH (port 22) and RDP (port 3389) access to specific IP ranges. Never allow 0.0.0.0/0.",
	"evidence_type": "automated",
}

# AWS Security Groups
violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_ssh == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows SSH (port 22) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 22,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:security-group"
	input.data.open_rdp == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security group '%s' allows RDP (port 3389) from 0.0.0.0/0", [input.data.group_name]),
		"details": {
			"group_id": input.data.group_id,
			"group_name": input.data.group_name,
			"port": 3389,
		},
	}
}

# GCP Firewall Rules
violations contains violation if {
	input.resource_type == "gcp:compute:firewall"
	input.data.open_ssh == true
	input.data.disabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Firewall rule '%s' allows SSH (port 22) from 0.0.0.0/0", [input.data.name]),
		"details": {
			"name": input.data.name,
			"port": 22,
		},
	}
}

violations contains violation if {
	input.resource_type == "gcp:compute:firewall"
	input.data.open_rdp == true
	input.data.disabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Firewall rule '%s' allows RDP (port 3389) from 0.0.0.0/0", [input.data.name]),
		"details": {
			"name": input.data.name,
			"port": 3389,
		},
	}
}
