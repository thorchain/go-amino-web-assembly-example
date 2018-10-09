package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	secp256k1 "github.com/tendermint/btcd/btcec"
	"github.com/tendermint/go-amino"
	"syscall/js"
)

var beforeUnloadCh = make(chan struct{})

func main() {
	fmt.Println("Go WebAssembly")

	callback := js.NewCallback(signMessage)
	defer callback.Release()
	setSignMessage := js.Global().Get("setSignMessage")
	setSignMessage.Invoke(callback)

	beforeUnloadCb := js.NewEventCallback(0, beforeUnload)
	defer beforeUnloadCb.Release()
	addEventListener := js.Global().Get("addEventListener")
	addEventListener.Invoke("beforeunload", beforeUnloadCb)

	<-beforeUnloadCh
	fmt.Println("bye :-)")
}

func NewCodec() *amino.Codec {
	cdc := amino.NewCodec()
	cdc.RegisterConcrete(MsgSign{}, "example/MsgSign", nil)
	return cdc
}

type MsgSign struct {
	PubKey string `json:"pubKey"`
	PrivKey string `json:"privKey"`
	Issuer   string `json:"issuer"`
	Receiver string `json:"receiver"`
}

func signMessage(args []js.Value) {
	message := args[0].String()
	b := []byte(message)
	var msg MsgSign
	if err := json.Unmarshal(b, &msg); err != nil {
		panic(err)
	}
	fmt.Printf("message: %v\n", msg)
	fmt.Println("-->", msg)

	cdc := NewCodec()

	msgB, err := cdc.MarshalBinary(msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("msg amino binary: %v\n", msgB)
	fmt.Printf("msg amino hex: %v\n", hex.EncodeToString(msgB))

	receiveAminoBinaryEncodedMessage := js.Global().Get("receiveAminoBinaryEncodedMessage")
	receiveAminoBinaryEncodedMessage.Invoke(string(msgB))

	receiveSignature := js.Global().Get("receiveSignature")
	sig, err := sign(msgB, msg.PrivKey)
	if err != nil {
		panic(err)
	}
	receiveSignature.Invoke(hex.EncodeToString(sig))
}

func Sha256(bytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}

func sign(msg []byte, privKeyHex string) ([]byte, error) {
	fmt.Println("sha256", hex.EncodeToString(Sha256(msg)))
	privKey, _ := hex.DecodeString(privKeyHex)
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	sig, err := priv.Sign(Sha256(msg))
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func beforeUnload(event js.Value) {
	beforeUnloadCh <- struct{}{}
}