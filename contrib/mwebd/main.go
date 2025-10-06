package main

import "C"

import (
	"runtime"
	"unsafe"

	"github.com/ltcmweb/ltcd/ltcutil/scrypt"
	"github.com/ltcmweb/mwebd"
)

//export Start
func Start(chain, dataDir string) C.int {
	server, err := mwebd.NewServer(chain, dataDir, "")
	if err != nil {
		return 0
	}
	if runtime.GOOS != "windows" {
		if server.StartUnix(dataDir+"/mwebd.sock") == nil {
			return 1
		}
	} else if port, err := server.Start(0); err == nil {
		return C.int(port)
	}
	return 0
}

//export Scrypt
func Scrypt(x string, buf *byte) {
	copy(unsafe.Slice(buf, 32), scrypt.Scrypt([]byte(x)))
}

func main() {}
