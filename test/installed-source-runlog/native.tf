variable "workspace" {
  type = string
}

output "lock_targets" {
  value = {
    lock_free_types = ["terraform_data"]
  }
}
