// Package fixturehygiene hosts the automated test for the WU-0.3 secret/PII
// fixture gate. The gate itself is a shell script (scripts/check-fixtures.sh)
// so it can run standalone in CI and from `make`; this package's test drives
// that script over synthetic fixtures so `go test ./...` proves it both
// catches planted secrets and passes a clean tree (and the agreed
// placeholders). There is no runtime code here.
package fixturehygiene
