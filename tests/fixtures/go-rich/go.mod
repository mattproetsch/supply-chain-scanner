module example.com/fixture-go-rich

go 1.22

require (
	github.com/spf13/cobra v1.8.0
	example.com/pseudo v0.0.0-20231201120000-abcdef012345
	example.com/incompat v2.0.0+incompatible
)

require github.com/single/line v1.2.3

replace github.com/old/lib => github.com/new/lib v1.0.0

replace (
	github.com/another/lib => ../local
)
