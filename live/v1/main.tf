provider "aws" {
  region = "us-east-1"
}

module "template" {
  source = "../../module/services/template"
  ver = "v1"
  region = "us-east-1"
}
