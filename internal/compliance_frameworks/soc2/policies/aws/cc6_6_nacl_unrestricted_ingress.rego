# METADATA
# title: CC6.6 - NACL Unrestricted Ingress on Admin Ports
# description: Network ACLs should not allow unrestricted inbound access on admin ports
# scope: package
package sigcomply.soc2.cc6_6_nacl_unrestricted_ingress

metadata := {
	"id": "soc2-cc6.6-nacl-unrestricted-ingress",
	"name": "NACL Unrestricted Admin Port Ingress",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:network-acl"],
	"remediation": "Update Network ACL entries to restrict inbound access on admin ports (22, 3389) to specific CIDR ranges instead of 0.0.0.0/0.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:network-acl"
	input.data.unrestricted_ssh_ingress == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Network ACL '%s' allows unrestricted SSH (port 22) ingress from 0.0.0.0/0", [input.data.network_acl_id]),
		"details": {
			"network_acl_id": input.data.network_acl_id,
			"vpc_id": input.data.vpc_id,
			"port": 22,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:ec2:network-acl"
	input.data.unrestricted_rdp_ingress == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Network ACL '%s' allows unrestricted RDP (port 3389) ingress from 0.0.0.0/0", [input.data.network_acl_id]),
		"details": {
			"network_acl_id": input.data.network_acl_id,
			"vpc_id": input.data.vpc_id,
			"port": 3389,
		},
	}
}
