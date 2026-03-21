# METADATA
# title: CC6.7 - Minimum TLS Version
# description: Load balancers and CDN distributions must use TLS 1.2 or higher
# scope: package
package sigcomply.soc2.cc6_7_tls_minimum

metadata := {
	"id": "soc2-cc6.7-tls-minimum",
	"name": "Minimum TLS 1.2 Required",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elbv2:load-balancer", "aws:cloudfront:distribution"],
	"remediation": "Update SSL/TLS policy to use TLS 1.2+: For ELB, use ELBSecurityPolicy-TLS13-1-2-2021-06 or similar. For CloudFront, set minimum protocol version to TLSv1.2_2021.",
}

# TLS 1.2+ compatible ELB security policies
tls12_policies := {
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
}

# TLS 1.2+ compatible CloudFront minimum protocol versions
tls12_cf_versions := {
	"TLSv1.2_2018",
	"TLSv1.2_2019",
	"TLSv1.2_2021",
}

# ELB listener with weak SSL policy
violations contains violation if {
	input.resource_type == "aws:elbv2:load-balancer"
	listener := input.data.listeners[_]
	listener.ssl_policy != ""
	not tls12_policies[listener.ssl_policy]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Load balancer '%s' listener on port %d uses SSL policy '%s' which may not enforce TLS 1.2+", [input.data.name, listener.port, listener.ssl_policy]),
		"details": {
			"lb_name": input.data.name,
			"port": listener.port,
			"ssl_policy": listener.ssl_policy,
		},
	}
}

# CloudFront with old TLS version
violations contains violation if {
	input.resource_type == "aws:cloudfront:distribution"
	input.data.minimum_protocol_version != ""
	not tls12_cf_versions[input.data.minimum_protocol_version]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudFront distribution '%s' uses minimum TLS version '%s' which is below TLS 1.2", [input.data.domain_name, input.data.minimum_protocol_version]),
		"details": {
			"domain_name": input.data.domain_name,
			"minimum_protocol_version": input.data.minimum_protocol_version,
		},
	}
}
