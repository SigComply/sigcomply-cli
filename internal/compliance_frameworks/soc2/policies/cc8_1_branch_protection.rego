# METADATA
# title: CC8.1 - GitHub Branch Protection Required
# description: GitHub repositories should have branch protection enabled on the default branch
# scope: package
# schemas:
#   - input: schema.input
package sigcomply.soc2.cc8_1_branch_protection

metadata := {
	"id": "soc2-cc8.1-branch-protection",
	"name": "GitHub Branch Protection Required",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["github:repository"],
	"remediation": "Enable branch protection on the default branch. Go to Repository Settings > Branches > Add branch protection rule for the default branch.",
}

# violations contains a violation if branch protection is not enabled
violations contains violation if {
	input.resource_type == "github:repository"
	not has_branch_protection
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Repository '%s' does not have branch protection enabled on the default branch '%s'", [input.data.full_name, input.data.default_branch]),
		"details": {
			"repository": input.data.full_name,
			"default_branch": input.data.default_branch,
			"visibility": input.data.visibility,
		},
	}
}

# violations contains a violation if branch protection exists but doesn't require PR reviews
violations contains violation if {
	input.resource_type == "github:repository"
	has_branch_protection
	not requires_pull_request
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Repository '%s' has branch protection but does not require pull request reviews", [input.data.full_name]),
		"details": {
			"repository": input.data.full_name,
			"default_branch": input.data.default_branch,
			"branch_protection_enabled": true,
			"require_pull_request": false,
		},
	}
}

# Helper to check if branch protection is enabled
has_branch_protection if {
	input.data.branch_protection != null
	input.data.branch_protection.enabled == true
}

# Helper to check if PR reviews are required
requires_pull_request if {
	input.data.branch_protection.require_pull_request == true
}
