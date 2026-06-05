# synthetic-lab: true
# purpose: synthetic broad IAM-style policy sample for offline defensive review

resource "synthetic_iam_policy" "broad_policy" {
  name          = "fake-lab-role"
  owner_account = "123456789012"
  principal     = "lab-user"
  role_arn      = "arn:aws:iam::123456789012:role/fake-lab-role"
  actions       = ["synthetic:*"]
  resources     = ["*"]
}
