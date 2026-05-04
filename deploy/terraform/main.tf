terraform {
  required_version = ">= 1.5.0"
}

variable "opad_allowed_cidrs" {
  type = list(string)
  description = "Authorized CTF/lab game networks only."
}

output "opad_security_notes" {
  value = [
    "Expose OPAD only to team VPN/management network.",
    "Capture only authorized game CIDRs.",
    "Do not route exploit workers outside configured target scope."
  ]
}
