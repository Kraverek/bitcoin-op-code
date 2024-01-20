package mempoolApi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/pkg/errors"
)

type PrevOut struct {
	Script  string `json:"scriptpubkey"`
	Asm     string `json:"scriptpubkey_asm"`
	Type    string `json:"scriptpubkey_type"`
	Address string `json:"scriptpubkey_address"`
	Value   int64  `json:"value"`
}

type Vin struct {
	Txid                  string   `json:"txid"`
	Vout                  int      `json:"vout"`
	PrevOut               PrevOut  `json:"prevout"`
	ScriptSig             string   `json:"scriptsig"`
	ScriptSigAsm          string   `json:"scriptsig_asm"`
	Witness               []string `json:"witness"`
	IsCoinBase            bool     `json:"is_coinbase"`
	Sequence              uint64   `json:"sequence"`
	InnerWitnessScriptAsm string   `json:"inner_witnessscript_asm,omitempty"`
}

type Vout struct {
	Script  string `json:"scriptpubkey"`
	Asm     string `json:"scriptpubkey_asm"`
	Type    string `json:"scriptpubkey_type"`
	Address string `json:"scriptpubkey_address"`
	Value   int64  `json:"value"`
}

type TxStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height"`
	BlockHash   string `json:"block_hash"`
	BlockTime   int64  `json:"block_time"`
}

type TxRawResult struct {
	Txid     string   `json:"txid"`
	Version  int      `json:"version"`
	LockTime int      `json:"locktime"`
	Vin      []Vin    `json:"vin"`
	Vout     []Vout   `json:"vout"`
	Size     int      `json:"size"`
	Weight   int      `json:"weight"`
	SigOps   int      `json:"sigops"`
	Fee      int64    `json:"fee"`
	Status   TxStatus `json:"status"`
}

func (c *MempoolClient) GetRawTransaction(txHash *chainhash.Hash) (*wire.MsgTx, error) {
	res, err := c.request(http.MethodGet, fmt.Sprintf("/tx/%s", txHash.String()), nil)
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(res)); err != nil {
		return nil, err
	}
	return tx, nil
}

func (c *MempoolClient) GetTransactionDetails(txHash *chainhash.Hash) (*TxRawResult, error) {
	res, err := c.request(http.MethodGet, fmt.Sprintf("/tx/%s", txHash.String()), nil)
	if err != nil {
		return nil, err
	}

	var tx TxRawResult
	err = json.Unmarshal(res, &tx)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}

func (c *MempoolClient) BroadcastTx(tx *wire.MsgTx) (*chainhash.Hash, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	res, err := c.request(http.MethodPost, "/tx", strings.NewReader(hex.EncodeToString(buf.Bytes())))
	if err != nil {
		return nil, err
	}

	txHash, err := chainhash.NewHashFromStr(string(res))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to parse tx hash, %s", string(res)))
	}
	return txHash, nil
}
