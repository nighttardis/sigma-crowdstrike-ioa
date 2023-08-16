# sigma-crowdstrike-ioa
The goal of this project is to provde a way to convert sigma rules into Crowdstrike Custom IOAs. 

In it's current state it won't work, depending on my schedule I may continue to work on it.

## Features
* Retrieve API keys from hashicorp vault
* Parse a single sigma rule or an entire directory

## Limitations
* Currently won't attempt to create custom IOAs
    * Futher testing needs to be done on how to build the IOAs
    * Futher testing needs to be done on how to retrive the correct custom ioa group, disposition id, custom ioa rule type
* Will only parse basic sigma rules
    * no "nots" or anything complex with "and" or "or"
    * not sure if it would be possible with IOAs to fully implement those options
* Static set of field mappings in [sigma.go](utilities/sigma.go)
* Hashicorp Vault authentication is only username and password

## Execution

```sh 
go build
./sigma_crowdstrike_ioa [--config-path (path to file) {config.xml}] (<--sigma-path (path to directory of sigma rules)> | <--sigma-rule (path to single sigma rule to convert)>)
```


## Config
config.yaml
```
auth:
  type: #str (plaintext|hvault)
  hvault:
    vault_address: <vault address>
    username: <vault username>
    password: <vault password>
    cs_client_id: <name of the value containing the client id>
    cs_client_secret: <name of the value containing the client sceret>
    mount_path: <mount path within hashcorp>
    key: <key at the mount_path>
  plaintext:
    cs_client_id: <cs client id>
    cs_client_secret: <cs client sceret>
cs_cloud: <cs environment> (us-1, us-2, etc)
mapping:
  process_creation: # logsource.category
    experimental: monitor # sigma staus -> cs disposition
    detect: detect
    production: kill_process
```