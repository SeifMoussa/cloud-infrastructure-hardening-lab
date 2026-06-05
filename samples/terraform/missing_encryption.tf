# synthetic-lab: true
# purpose: synthetic missing encryption sample for offline defensive review

resource "synthetic_storage_bucket" "lab_unencrypted_bucket" {
  name              = "lab-public-bucket"
  owner_account     = "123456789012"
  encryption_status = "disabled"
}
