# METADATA
# title: SigComply Shared Helpers
# description: Common helper functions for SigComply policies
# scope: package
package sigcomply.lib

# is_aws_resource checks if the input is an AWS resource
is_aws_resource if {
	startswith(input.resource_type, "aws:")
}

# is_resource_type checks if the input matches a specific resource type
is_resource_type(expected) if {
	input.resource_type == expected
}

# has_tag checks if a resource has a specific tag
has_tag(key) if {
	input.data.tags[key]
}

# tag_value returns the value of a specific tag
tag_value(key) := value if {
	value := input.data.tags[key]
}

# is_encrypted checks common encryption fields
is_encrypted if {
	input.data.encryption_enabled == true
}

is_encrypted if {
	input.data.encrypted == true
}

# count_resources counts resources matching a type in batched mode
count_resources_by_type(resource_type) := count([r |
	some i
	r := input.resources[i]
	r.resource_type == resource_type
])

# filter_resources returns resources matching a type in batched mode
filter_resources_by_type(resource_type) := [r |
	some i
	r := input.resources[i]
	r.resource_type == resource_type
]
