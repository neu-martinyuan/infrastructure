variable "region" {
  type = string
}

variable "cidr_block" {
  type = string
  default = "10.0.0.0/16"
}

variable "subnet_cidr_block" {
  type = "list"
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "azs" {
	type = "list"
	default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "ver" {
  type = string

}

variable "rt_cidr_block" {
  type = string
  default = "0.0.0.0/0"
}
