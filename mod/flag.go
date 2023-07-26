package mod

import "flag"

var (
	WorkerCount int
	TokenFile   string
	DictFile    string
)

func init() {

	flag.IntVar(&WorkerCount, "c", 100, "set concurrent workers")
	flag.StringVar(&TokenFile, "t", "jwt.txt", "File containing JWT token(s)")
	flag.StringVar(&DictFile, "d", "pass.txt", "Dictionary file. If ommited, will read from stdin")

}
