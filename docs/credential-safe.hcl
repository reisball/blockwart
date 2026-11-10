ui = false
api_addr = "http://credential-safe:8200"
cluster_addr = "http://127.0.0.1:8201"
storage "raft" {
  node_id = "blockwart"
  path = "/openbao/data"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
seal "static" {
  current_key_id = "blockwart-v1-1"
  current_key = "file:///openbao/secrets/unseal.key"
}
