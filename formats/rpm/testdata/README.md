`snail-demo-1.2.3-4.noarch.rpm` was produced by `rpmbuild` from the spec in
`inspect_test.go`. It is committed rather than generated because a parser tested
only against fixtures it also writes will agree with itself about a format it
has misread — which is exactly how a defect reached the Debian inspector, where
every real package was refused and every test passed.
