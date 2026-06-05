# synthetic-lab: true
# purpose: synthetic clean storage bucket sample for offline defensive review

resource "synthetic_storage_bucket" "clean_bucket" {
  name              = "lab-clean-bucket"
  owner_account     = "123456789012"
  public_read       = false
  encryption_status = "enabled"
  logging_status    = "enabled"
}
