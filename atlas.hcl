// Atlas configuration for ShipIt Server
env "dev" {
  src = "file://db/schema"
  dev = "docker://postgres/16/dev?search_path=public"
  migration {
    dir = "file://db/migrations"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

env "prod" {
  src = "file://db/schema"
  url = getenv("DATABASE_URL")
  migration {
    dir = "file://db/migrations"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
} 