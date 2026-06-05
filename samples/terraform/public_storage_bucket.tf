# synthetic-lab: true
# purpose: synthetic public storage bucket sample for offline defensive review

resource "synthetic_storage_bucket" "lab_public_bucket" {
  name           = "lab-public-bucket"
  owner_account  = "123456789012"
  website_domain = "lab.example.com"
  public_read    = true
}
