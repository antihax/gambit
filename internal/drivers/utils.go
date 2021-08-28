package drivers

import (
	"crypto/sha1"
	"encoding/hex"

	"github.com/antihax/gambit/internal/store"
)

func GetHash(b []byte) string {
	h := sha1.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func StoreHash(buf []byte, storeChan chan store.File) string {
	hash := GetHash(buf)
	storeChan <- store.File{
		Filename: hash,
		Location: "raw",
		Data:     buf,
	}
	return hash
}
