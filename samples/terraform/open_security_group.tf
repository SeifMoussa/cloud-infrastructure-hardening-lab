# synthetic-lab: true
# purpose: synthetic open security group sample for offline defensive review

resource "synthetic_security_group" "lab_security_group" {
  name          = "lab-security-group"
  owner_account = "123456789012"

  ingress {
    description = "Synthetic admin access range for lab review"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr        = "203.0.113.0/24"
  }
}
