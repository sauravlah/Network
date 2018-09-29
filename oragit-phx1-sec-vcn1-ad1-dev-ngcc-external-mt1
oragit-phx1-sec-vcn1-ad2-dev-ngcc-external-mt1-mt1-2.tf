
resource "oci_core_security_list" "oragit-phx1-sec-vcn1-dev-ngcc-external-mt1" {
    compartment_id  =   "${var.sandbox_compartment_git_networks_ocid}"
    display_name    =   "oragit-phx1-sec-vcn1-dev-ngcc-external-mt1"
    vcn_id          =   "${oci_core_virtual_network.oragit-ash1-vcn1.id}"
None	{
	tcp_options	{
		"max"	= "22"
		"min"	= "22"
		}
		stateless = "false"
		protocol = "${var.Protocol-SSH}"
		source = "oragit-ash1-net-vcn1-ad1-nonprod-ngcc-tools-gpia-internal-mt2"
	},
###############INGRESS SECLIST RULE FROM DESTINATION o to SOURCE o AND THIS IS THE 1th RULE
resource "oci_core_security_list" "oragit-phx1-sec-vcn1-dev-ngcc-external-mt1" {
    compartment_id  =   "${var.sandbox_compartment_git_networks_ocid}"
    display_name    =   "oragit-phx1-sec-vcn1-dev-ngcc-external-mt1"
    vcn_id          =   "${oci_core_virtual_network.oragit-ash1-vcn1.id}"
None	{
	tcp_options	{
		"max"	= "22"
		"min"	= "22"
		}
		stateless = "false"
		protocol = "${var.Protocol-SSH}"
		source = "oragit-ash1-net-vcn1-ad2-nonprod-ngcc-tools-gpia-internal-mt2"
	},
###############INGRESS SECLIST RULE FROM DESTINATION r to SOURCE r AND THIS IS THE 1th RULE