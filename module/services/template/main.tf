# VPC
resource "aws_vpc" "vpc" {
  cidr_block                       = var.cidr_block
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "vpc-${var.ver}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "terra_igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "ig-${var.ver}"
  }
}

# subnet
resource "aws_subnet" "subnet123" {
  count                   = length(var.subnet_cidr_block)
  cidr_block              = element(var.subnet_cidr_block, count.index)
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-${count.index}-${var.ver}"
  }
}


# Route table: attach Internet Gateway
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.rt_cidr_block
    gateway_id = aws_internet_gateway.terra_igw.id
  }
  tags = {
    Name = "rt-${var.ver}"
  }
}

# Route table association with public subnets
resource "aws_route_table_association" "a" {
  count          = length(var.subnet_cidr_block)
  subnet_id      = element(aws_subnet.subnet123.*.id, count.index)
  route_table_id = aws_route_table.public_rt.id
}

# Security group - application
resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id



  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application-${var.ver}"
  }
}

# Security group ingress rule - application
resource "aws_security_group_rule" "sample" {
  count             = length(var.port)
  type              = "ingress"
  from_port         = element(var.port, count.index)
  to_port           = element(var.port, count.index)
  protocol          = "tcp"
  cidr_blocks       = [var.sg_rule_cidr_block]
  security_group_id = aws_security_group.application.id
}

# Security group ingress rule - application 3306 port
resource "aws_security_group_rule" "rule1" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = [var.mysql_cidr_block]
  security_group_id = aws_security_group.application.id
}

# Security group - database
resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
    cidr_blocks     = [var.mysql_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database-${var.ver}"
  }
}

# IAM policy
resource "aws_iam_policy" "policy" {
  name        = var.iam_name
  path        = var.iam_path
  description = "allow EC2 instances to perform S3 buckets"

  policy = var.iam_policy
}

resource "aws_iam_role" "role" {
  name = var.aws_iam_role_name

  assume_role_policy = var.iam_assume_role_policy
}

resource "aws_iam_policy_attachment" "attach" {
  name       = var.aws_iam_policy_attachment_name
  roles      = [aws_iam_role.role.name]
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "profile" {
  name = "ec2_profile"
  role = aws_iam_role.role.name
}

# Start to create RDS
locals {
  resource_name_prefix = "${var.namespace}-${var.ver}"
}

resource "aws_db_subnet_group" "_" {
  name       = "${local.resource_name_prefix}-subnet-group"
  subnet_ids = [element(aws_subnet.subnet123.*.id, 1), element(aws_subnet.subnet123.*.id, 2)]
}

resource "aws_db_instance" "_" {
  identifier = "${local.resource_name_prefix}-${var.rds_identifier}"

  allocated_storage       = var.rds_allocated_storage
  backup_retention_period = var.rds_backup_retention_period
  backup_window           = var.rds_backup_window
  maintenance_window      = var.rds_maintenance_window
  db_subnet_group_name    = aws_db_subnet_group._.id
  engine                  = var.rds_engine
  engine_version          = var.rds_engine_version
  instance_class          = var.rds_instance_class
  multi_az                = var.multi_az
  name                    = var.rds_name
  username                = var.rds_username
  password                = var.password
  port                    = var.rds_port
  publicly_accessible     = var.rds_publicly_accessible
  storage_encrypted       = var.rds_storage_encrypted
  storage_type            = var.storage_type

  vpc_security_group_ids = [aws_security_group.database.id]

  allow_major_version_upgrade = false
  auto_minor_version_upgrade  = true

  final_snapshot_identifier = null
  snapshot_identifier       = ""
  skip_final_snapshot       = true

  performance_insights_enabled = false
}

resource "random_string" "password" {
  length  = 8
  special = false
}

# Start to create EC2
resource "aws_key_pair" "auth" {
  key_name   = var.ec2_key_name
  public_key = var.ec2_public_key
}

data "aws_ami" "ami" {
  most_recent = var.ec2_aws_ami

  #filter {
  #  name   = "AMI Name"
  #  values = ["csye6225_*"]
  #}

  owners = [var.dev_account]
}

resource "aws_instance" "ubuntu" {
  ami = data.aws_ami.ami.id
  connection {
    # The default username for our AMI
    user = "ec2-user"
    host = "${aws_instance.ubuntu.public_ip}"
    # The connection will use the local SSH agent for authentication.
  }
  instance_type           = var.instance_type
  key_name                = "${aws_key_pair.auth.id}"
  vpc_security_group_ids  = [aws_security_group.application.id]
  subnet_id               = element(aws_subnet.subnet123.*.id, 3)
  disable_api_termination = var.ec2_disable_api_termination
  user_data               = <<EOF
#!/bin/bash
echo export DB_USERNAME="${var.DB_USERNAME}" >> /etc/profile
echo export DB_PASSWORD="${var.DB_PASSWORD}" >> /etc/profile
echo export DB_NAME="${var.DB_NAME}" >> /etc/profile
echo export HOSTNAME="${aws_db_instance._.endpoint}" >> /etc/profile
echo export BUCKET_NAME="${var.s3_bucket_name}" >> /etc/profile
  EOF

  iam_instance_profile = "${aws_iam_instance_profile.profile.name}"

  root_block_device {
    delete_on_termination = var.ec2_delete_on_termination
    volume_size           = var.ec2_volume_size
    volume_type           = var.ec2_volume_type
  }

  tags = {
    Name = "ubuntu-${var.ver}"
  }
}

# create dynamodb
resource "aws_dynamodb_table" "table" {
  name           = var.dy_name
  hash_key       = var.dy_hash_key
  read_capacity  = var.dy_read_capacity
  write_capacity = var.dy_write_capacity

  attribute {
    name = var.dy_attribute_name
    type = var.dy_attribute_type
  }
}

# create s3
resource "aws_s3_bucket" "s3" {
  bucket        = var.s3_bucket_name
  force_destroy = var.s3_force_destroy
  acl           = var.s3_acl
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        #kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm = var.s3_sse_algorithm
      }
    }
  }

  lifecycle_rule {
    enabled = var.s3_lifecycle_enabled

    noncurrent_version_transition {
      days          = var.s3_days
      storage_class = var.s3_storage_class
    }
  }

  tags = {
    Name = var.s3_bucket_name
  }
}
