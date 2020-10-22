resource "aws_vpc" "_" {
  cidr_block = var.vpc_cidr

  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames
}

resource "aws_internet_gateway" "_" {
  vpc_id = aws_vpc._.id
}

resource "aws_route_table" "_" {
  vpc_id = aws_vpc._.id

  dynamic "route" {
    for_each = var.route

    content {
      cidr_block     = route.value.cidr_block
      gateway_id     = route.value.gateway_id
      instance_id    = route.value.instance_id
      nat_gateway_id = route.value.nat_gateway_id
    }
  }
}

resource "aws_route_table_association" "_" {
  count          = length(var.subnet_ids)

  subnet_id      = element(var.subnet_ids, count.index)
  route_table_id = aws_route_table._.id
}

module "vpc" {
  source = "../../modules/vpc"

  resource_tag_name = var.resource_tag_name
  namespace         = var.namespace
  region            = var.region

  vpc_cidr = "10.0.0.0/16"

  route = [
    {
      cidr_block     = "0.0.0.0/0"
      gateway_id     = module.vpc.gateway_id
      instance_id    = null
      nat_gateway_id = null
    }
  ]

  subnet_ids = module.subnet_ec2.ids
}

locals {
  resource_name_prefix = "${var.namespace}-${var.resource_tag_name}"
}

resource "aws_instance" "_" {
  ami                         = var.ami
  instance_type               = var.instance_type
  user_data                   = var.user_data
  subnet_id                   = var.subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  key_name                    = aws_key_pair._.key_name
  vpc_security_group_ids      = var.vpc_security_group_ids

  iam_instance_profile = var.iam_instance_profile
}

resource "aws_eip" "_" {
  vpc      = true
  instance = aws_instance._.id
}

resource "tls_private_key" "_" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "_" {
  key_name   = var.key_name
  public_key = tls_private_key._.public_key_openssh
}
