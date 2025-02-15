# TODO

### Setup web3signer

- Run in Docker or install `postrgresql` and create DB named `web3signer`

```bash
  docker run -e POSTGRES_PASSWORD=password -e POSTGRES_USER=postgres -e POSTGRES_DB=web3signer -p 5432:5432 postgres
```

- Download and unpack `web3signer` from https://github.com/Consensys/web3signer/releases
- Apply all migrations from V1 to V12 in `web3signer`'s `migrations/postgresql` folder maintaining their order and replacing `${MIGRATION_NAME}.sql` with the migration name

```bash
  psql --echo-all --host=localhost --port=5432 --dbname=web3signer --username=postgres -f ./${MIGRATION_NAME}.sql
```

- Run `web3signer`, you might need to change HTTP port, Ethereum network and PostgreSQL address
```bash
  web3signer --http-listen-port=8010 eth2 --network=holesky --slashing-protection-db-url="jdbc:postgresql://localhost/web3signer"  --slashing-protection-db-username=postgres --slashing-proteion-db-password=password --key-manager-api-enabled=true
```