terraform {
  required_version = ">= 0.13"

  required_providers {
    mongodb = {
      source = "Kaginari/mongodb"
    }
  }
}

provider "mongodb" {
  host = "127.0.0.1"
  port = "27017"
  username = "root"
  password = "root"
  auth_database = "admin"
}

variable "username" {
  description = "the user name"
  default = "monta"
}
variable "password" {
  description = "the user password"
  default = "monta"
}

resource "mongodb_db_role" "role" {
  name = "custom_role_test"
  privilege {
    db = "admin"
    collection = "*"
    actions = ["collStats"]
  }
  privilege {
    db = "ds"
    collection = "*"
    actions = ["collStats"]
  }


}

resource "mongodb_db_role" "role_2" {
  depends_on = [mongodb_db_role.role]
  database = "admin"
  name = "new_role3"
  inherited_role {
    role = mongodb_db_role.role.name
    db =   "admin"
  }
}
resource "mongodb_db_role" "role4" {
  depends_on = [mongodb_db_role.role]
  database = "exemple"
  name = "new_role4"
}

resource "mongodb_db_user" "user" {
  auth_database = "exemple"
  name = "monta"
  password = "monta"
  role {
    role = mongodb_db_role.role.name
    db =   "admin"
  }
  role {
    role = "readAnyDatabase"
    db =   "admin"
  }

}