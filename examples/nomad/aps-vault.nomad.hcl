# APS Vault as a Nomad job (0.36): one group, two tasks on a shared bridge network — the frontend's nginx
# publishes port 8087 and proxies /api/ to the backend, which is reachable only inside the group.
#   nomad var put nomad/jobs/aps-vault init_token="$(openssl rand -hex 24)" sso_unlock_key="$(openssl rand -base64 32)"
#   nomad job run examples/nomad/aps-vault.nomad.hcl
# The data directory is a host volume (SQLite → a single allocation pinned by the volume); for several
# backends use PostgreSQL (VAULT_DATABASE_URL) and docs/CLUSTER.md.
job "aps-vault" {
  datacenters = ["dc1"]
  type        = "service"

  group "vault" {
    count = 1

    network {
      mode = "bridge"
      port "http" {
        static = 8087
        to     = 80
      }
    }

    volume "data" {
      type      = "host"
      source    = "aps-vault-data" # client { host_volume "aps-vault-data" { path = "/srv/aps-vault" } }
      read_only = false
    }

    restart {
      attempts = 3
      interval = "5m"
      delay    = "15s"
      mode     = "delay"
    }

    task "backend" {
      driver = "docker"

      config {
        image = "ghcr.io/kzhebenev/aps-vault/backend:0.41.12"
      }

      volume_mount {
        volume      = "data"
        destination = "/app/data"
      }

      env {
        VAULT_DATA_DIR   = "/app/data"
        VAULT_PUBLIC_URL = "https://vault.example.com"
      }

      # secrets come from Nomad variables, rendered into a file the entrypoint reads (never into the job spec)
      template {
        destination = "secrets/vault.env"
        env         = true
        data        = <<-EOT
          {{ with nomadVar "nomad/jobs/aps-vault" }}
          VAULT_INIT_TOKEN={{ .init_token }}
          VAULT_SSO_UNLOCK_KEY={{ .sso_unlock_key }}
          {{ end }}
        EOT
      }

      service {
        name     = "aps-vault-backend"
        port     = "http"
        provider = "nomad"
        check {
          type     = "http"
          path     = "/api/health"
          port     = 8086
          interval = "30s"
          timeout  = "5s"
        }
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }

    task "frontend" {
      driver = "docker"

      config {
        image = "ghcr.io/kzhebenev/aps-vault/frontend:0.41.12"
        ports = ["http"]
      }

      env {
        VAULT_BACKEND_URL = "http://127.0.0.1:8086" # same bridge network namespace as the backend task
      }

      service {
        name     = "aps-vault"
        port     = "http"
        provider = "nomad"
        check {
          type     = "http"
          path     = "/"
          interval = "30s"
          timeout  = "5s"
        }
      }

      resources {
        cpu    = 100
        memory = 64
      }
    }
  }
}
