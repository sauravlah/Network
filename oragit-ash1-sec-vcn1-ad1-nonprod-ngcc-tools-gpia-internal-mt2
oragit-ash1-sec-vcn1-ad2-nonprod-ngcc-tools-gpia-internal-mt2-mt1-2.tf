
resource "oci_core_security_list" "oragit-ash1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt2" {
    compartment_id  =   "${var.sandbox_compartment_git_networks_ocid}"
    display_name    =   "oragit-ash1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt2"
    vcn_id          =   "${oci_core_virtual_network.oragit-ash1-vcn1.id}"
None	{
	tcp_options	{
		"max"	= "22"
		"min"	= "22"
		}
		stateless = "false"
		protocol = "${var.Protocol-SSH}"
		destination = "oragit-phx1-net-vcn1-ad1-dev-ngcc-external-mt1"
	},
###############EGRESS SECLIST RULE FROM SOURCE o to DESTINATION o AND THIS IS THE 1th RULE
resource "oci_core_security_list" "oragit-ash1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt2" {
    compartment_id  =   "${var.sandbox_compartment_git_networks_ocid}"
    display_name    =   "oragit-ash1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt2"
    vcn_id          =   "${oci_core_virtual_network.oragit-ash1-vcn1.id}"
None	{
	tcp_options	{
		"max"	= "22"
		"min"	= "22"
		}
		stateless = "false"
		protocol = "${var.Protocol-SSH}"
		destination = "oragit-phx1-net-vcn1-ad2-dev-ngcc-external-mt1"
	},
###############EGRESS SECLIST RULE FROM SOURCE r to DESTINATION r AND THIS IS THE 1th RULE