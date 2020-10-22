provider "aws" {
  region = "us-east-1"
}

module "template" {
  source = "../../module/services/template"
  ver    = "v4"
  region = "us-east-1"
  #ami_key_pair_name = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2nPD8ZmsPsb0Y6VV8krykeygKKq9jPLwnScPJaWYt/T3Uh2jZOrgGLb8lLsH11rP7qig5iHS0pebJxcqyjaZnoTav7WOskz07CkoDXtpp9LyF9wZfkeczxl6o6YO9T5OQbFZWtVydpwdV2hdzC2gbfNkjGqKCr7iywld+ew5Wvwgc6BkFjDvOl2TEVWaXVFgnOjDuaNn4/wJi2eLF4kGTUGX66vWr2qUqcdYOLQ+jgGyOMu2OypVqKZWVjRjZeq/f674p5FKA9iryfcEUR254V4uM8+7ufYzXnlE23ixs/kvaYCokvqp8LWm/QH8q71eOB2iRHP+3H1crLdxvxLCoE1mgEe9Q+SWsi7ebmXxBoGRzjtcy42osC1tkYXhY4eyNY95j+vIwH7TOagPOkZIOyaXY4dsl4/yKtJR16QduuRrcScukaPjQdBr8lVW34mgRFrAkBr4HCsUIbUcH79IXn9cPX66zQFMv8vKJPd1vsvOeM8CfFudLq3R+hjQd/Yk= martin@chaoyi.local"
}


#module "services" {
#  source = "../modules/ec2ins"

#bucket_name = "webapp.jing.zhang"
#user_data = "#!/bin/bash\necho 'hello world'\nsudo hostname ubuntu\nexport DB_USERNAME=root\nexport DB_PASSWORD=MysqlPwd123\nexport Bucket_Name=webapp.jing.zhang"
#}
