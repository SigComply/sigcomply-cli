package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// exposurePolicies are checks on fields the shipped sources already
// collect: public exposure of workloads and repositories, standing admin
// access, idle accounts, and the defaults an org applies to new
// repositories. They mirror tests the SOC 2 automation platforms and the
// CIS benchmarks run (see each policy).
//
// Several read schema-optional fields. A filter or condition that reads
// an absent field errors the policy, so each optional field is guarded
// with isSet, which leaves records from a source that does not report
// the field out of the population (the iso27001 copies do the same).
func exposurePolicies() []core.Policy {
	return []core.Policy{
		// --- CC6.6: workloads off the public network -----------------
		autoPolicy{
			// CIS GCP 4.9; Drata "No external exposure of cloud resources".
			id: "soc2.cc6.6.no_public_compute_instances", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etComputeInstance},
			desc:    "Running compute instances have no public IP address.",
			rem:     "Remove public IPs from instances and reach them through a load balancer, NAT gateway or bastion.",
			clause:  allWhere(leaf("payload.is_running", "eq", true), leaf("payload.has_public_ip", "eq", false), "instance {{.payload.name}} has a public IP address"),
		}.policy(),
		autoPolicy{
			// CIS EKS 5.4.2, CIS GKE 5.6.4, CIS AKS 5.4.1.
			id: "soc2.cc6.6.private_kubernetes_endpoint", control: ctrlCC66, severity: core.SeverityMedium, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etKubernetesCluster},
			desc:    "Kubernetes control-plane endpoints are not publicly accessible.",
			rem:     "Make each cluster's API endpoint private, or restrict it to known networks.",
			clause:  allWhere(isSet("payload.is_private_endpoint"), leaf("payload.is_private_endpoint", "eq", true), "cluster {{.payload.name}} exposes a public control-plane endpoint"),
		}.policy(),

		// --- CC6.2 / CC6.3: who holds access --------------------------
		autoPolicy{
			// CIS AWS 1.12 (credentials unused for 45 days); 90 days here,
			// matching iso27001.5.16.inactive_user_accounts. unused_days is
			// deliberately unguarded in the condition: a directory that
			// cannot say how long an account has been idle cannot answer
			// this, and erroring says so (only aws.iam emits
			// directory_user.v2, and it always sets it).
			id: "soc2.cc6.2.inactive_user_accounts", control: ctrlCC62, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etDirectoryUserV2},
			desc:    "No active user account has gone unused for more than 90 days.",
			rem:     "Disable or remove accounts unused for more than 90 days; investigate accounts that never signed in.",
			clause:  allWhere(allOf(isSet("payload.is_active"), leaf("payload.is_active", "eq", true)), allOf(leaf("payload.unused_days", "gte", 0), leaf("payload.unused_days", "lte", 90)), "user {{.payload.display_name}} has been unused for more than 90 days (or never signed in)"),
		}.policy(),
		autoPolicy{
			// CIS AWS 1.16, CIS GCP 1.5; Drata "Least privilege".
			id: "soc2.cc6.3.no_broad_admin_iam_bindings", control: ctrlCC63, severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etIAMBinding},
			desc:    "No individual user holds an unconditional account- or project-wide admin role.",
			rem:     "Grant admin roles to groups, scope them with a condition, or replace them with narrower roles.",
			clause:  noneWhere(leaf("payload.principal_type", "eq", "user"), allOf(leaf("payload.is_broad_admin_role", "eq", true), leaf("payload.has_condition", "eq", false)), "user {{.payload.principal_id}} holds unconditional broad-admin role {{.payload.role}}"),
		}.policy(),
		autoPolicy{
			// CIS GitHub 1.3.x (admin and outside-collaborator access);
			// Azure CIS 1.5 for guests.
			id: "soc2.cc6.3.no_external_admins", control: ctrlCC63, severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: directoryUserTypes,
			desc:    "No external identity (outside collaborator, guest) holds administrator access.",
			rem:     "Remove admin rights from external identities, or bring the person into the organization.",
			clause:  none(allOf(isSet("payload.is_external"), leaf("payload.is_external", "eq", true), isSet("payload.is_admin"), leaf("payload.is_admin", "eq", true)), "external user {{.payload.display_name}} has administrator access"),
		}.policy(),
		autoPolicy{
			// CIS GitHub 1.2.2 (only admins create public repositories).
			id: "soc2.cc6.3.members_cannot_create_public_repos", control: ctrlCC63, also: []string{ctrlC11}, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etSourceControlOrgPolicy},
			desc:    "Organization members who are not admins cannot create public repositories.",
			rem:     "Restrict public repository creation to organization owners.",
			clause:  allWhere(isSet("payload.members_can_create_public_repos"), leaf("payload.members_can_create_public_repos", "eq", false), "organization {{.payload.id}} lets members create public repositories"),
		}.policy(),

		// --- C1.1: confidential source code ---------------------------
		autoPolicy{
			id: "soc2.c1.1.repositories_private", control: ctrlC11, also: []string{ctrlCC61}, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etGitRepository},
			desc:    "Source repositories are not public. Record an exception for intentionally open-source repositories.",
			rem:     "Make the repository private or internal, or record an exception if it is open source on purpose.",
			clause:  allWhere(isSet("payload.is_private"), leaf("payload.is_private", "eq", true), "repository {{.payload.name}} is public"),
		}.policy(),

		// --- CC6.1 / CC7.1: secure defaults for new repositories -------
		autoPolicy{
			// CIS GitHub 1.1.x (secret scanning); Secureframe "Secret scanning".
			id: "soc2.cc6.1.secret_scanning_on_by_default", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etSourceControlOrgPolicy},
			desc:    "Secret scanning is turned on by default for new repositories in the organization.",
			rem:     "Enable secret scanning for new repositories in the organization's code security settings.",
			clause:  allWhere(isSet("payload.secret_scanning_enabled_new_repos"), leaf("payload.secret_scanning_enabled_new_repos", "eq", true), "organization {{.payload.id}} does not enable secret scanning on new repositories"),
		}.policy(),
		autoPolicy{
			// Secureframe "Dependency testing"; Vanta Dependabot alert SLAs.
			id: "soc2.cc7.1.dependency_alerts_on_by_default", control: ctrlCC71, severity: core.SeverityMedium, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etSourceControlOrgPolicy},
			desc:    "Dependency vulnerability alerts are turned on by default for new repositories in the organization.",
			rem:     "Enable dependency alerts (Dependabot) for new repositories in the organization's code security settings.",
			clause:  allWhere(isSet("payload.dependabot_alerts_enabled_new_repos"), leaf("payload.dependabot_alerts_enabled_new_repos", "eq", true), "organization {{.payload.id}} does not enable dependency alerts on new repositories"),
		}.policy(),

		// --- CC7.1 / CC7.2: cluster patching and logging --------------
		autoPolicy{
			// Drata Test 310 (EKS audit logs); CIS EKS 2.1.1, CIS GKE 5.10.x.
			id: "soc2.cc7.2.kubernetes_control_plane_logging", control: ctrlCC72, severity: core.SeverityMedium, category: catLogging, cadence: cadenceDaily,
			accepts: []string{etKubernetesCluster},
			desc:    "Kubernetes control-plane (audit and API server) logging is enabled.",
			rem:     "Enable control-plane audit and API server logs on each cluster.",
			clause:  all(leaf("payload.logging_enabled", "eq", true), "cluster {{.payload.name}} does not log its control plane"),
		}.policy(),
		autoPolicy{
			// CIS GKE 5.5.3 (node auto-upgrade).
			id: "soc2.cc7.1.kubernetes_node_auto_upgrade", control: ctrlCC71, severity: core.SeverityLow, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etKubernetesCluster},
			desc:    "Kubernetes nodes upgrade automatically to patched versions.",
			rem:     "Turn on node auto-upgrade (or an automatic upgrade channel) for each cluster.",
			clause:  allWhere(isSet("payload.node_auto_upgrade_enabled"), leaf("payload.node_auto_upgrade_enabled", "eq", true), "cluster {{.payload.name}} does not upgrade its nodes automatically"),
		}.policy(),

		// --- CC8.1: what is deployed is what was approved --------------
		autoPolicy{
			// CIS AWS Foundations (ECR tag immutability); a mutable tag lets
			// an image be replaced after the change that shipped it.
			id: "soc2.cc8.1.container_image_tags_immutable", control: ctrlCC81, severity: core.SeverityLow, category: catChangeManagement, cadence: cadenceDaily,
			accepts: []string{etContainerRegistry},
			desc:    "Container registries do not allow an image tag to be overwritten.",
			rem:     "Turn on tag immutability for each registry or repository.",
			clause:  allWhere(isSet("payload.image_immutability_enabled"), leaf("payload.image_immutability_enabled", "eq", true), "registry {{.payload.name}} allows image tags to be overwritten"),
		}.policy(),
	}
}
