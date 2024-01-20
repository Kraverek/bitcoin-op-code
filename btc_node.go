package main

import (
	"bitcoin-op-code/pkg/btcapi"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
)

type Transaction struct {
	Txid          string `json:"txid"`
	Hash          string `json:"hash"`
	Version       int    `json:"version"`
	Size          int    `json:"size"`
	Vsize         int    `json:"vsize"`
	Weight        int    `json:"weight"`
	Locktime      int    `json:"locktime"`
	Vin           []Vin  `json:"vin"`
	Vout          []Vout `json:"vout"`
	Hex           string `json:"hex"`
	Blockhash     string `json:"blockhash"`
	Confirmations int    `json:"confirmations"`
	Time          int64  `json:"time"`
	Blocktime     int64  `json:"blocktime"`
}

type Vin struct {
	Txid        string   `json:"txid"`
	Vout        int      `json:"vout"`
	ScriptSig   Sig      `json:"scriptSig"`
	Txinwitness []string `json:"txinwitness"`
	Sequence    uint32   `json:"sequence"`
}

type Vout struct {
	Value        string    `json:"value"`
	N            int       `json:"n"`
	ScriptPubKey ScriptKey `json:"scriptPubKey"`
}

type Sig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

type ScriptKey struct {
	Asm     string `json:"asm"`
	Desc    string `json:"desc"`
	Hex     string `json:"hex"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

func get_node(network string) (*rpcclient.Client, error) {
	var connCfg *rpcclient.ConnConfig = nil

	if network == "mainnet" {
		connCfg = &rpcclient.ConnConfig{
			Host:         getStrEnv("NODE_HOST", "127.0.0.1:8332"),
			CookiePath:   ".cookie",
			Params:       chaincfg.MainNetParams.Name,
			HTTPPostMode: true,
			DisableTLS:   true,
		}
	} else if network == "testnet" {
		connCfg = &rpcclient.ConnConfig{
			Host:         getStrEnv("TESTNET_HOST", "127.0.0.1:18332"),
			User:         "qwe",
			Pass:         "qwe",
			Params:       chaincfg.TestNet3Params.Name,
			HTTPPostMode: true,
			DisableTLS:   true,
		}
	} else if network == "regtest" {
		connCfg = &rpcclient.ConnConfig{
			Host:         getStrEnv("REGTEST_HOST", "127.0.0.1:18443"),
			User:         "qwe",
			Pass:         "qwe",
			Params:       chaincfg.RegressionNetParams.Name,
			HTTPPostMode: true,
			DisableTLS:   true,
		}
	} else if network == "signet" {
		return nil, errors.New("signet Not implemented")
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		defer client.Shutdown()
		return nil, err
	}

	return client, nil
}

func getRawTransaction(network string, tx_hash string, tries ...int) (*btcjson.TxRawResult, error) {
	hash, err := chainhash.NewHashFromStr(tx_hash)
	if err != nil {
		return nil, err
	}

	attempts := 5
	if len(tries) > 0 {
		attempts = tries[0]
	}

	var txResult *btcjson.TxRawResult = nil
	var last_err error
	for attempts > 0 {
		attempts--
		node, err := get_node(network)
		if err != nil {
			last_err = err
			time.Sleep(time.Millisecond * 20)
			continue
		}
		txResult, err = node.GetRawTransactionVerbose(hash)
		if err != nil {
			last_err = err
			time.Sleep(time.Millisecond * 20)
			continue
		}
	}

	if txResult != nil {
		return txResult, nil
	}
	return nil, last_err
}

func getUnspentOutput(network string, utxo string) (*btcapi.UnspentOutput, error) {
	tx_hash, n, err := splitUtxoString(utxo)
	if err != nil {
		return nil, err
	}

	hash, err := chainhash.NewHashFromStr(tx_hash)
	if err != nil {
		return nil, err
	}

	tx, err := getRawTransaction(network, tx_hash)
	if err != nil {
		return nil, err
	}

	if int(n) >= len(tx.Vout) {
		return nil, fmt.Errorf("wrong input number of utxo %v tx has only %d inputs", utxo, len(tx.Vout))
	}

	vout := tx.Vout[n]

	script_bytes, err := hex.DecodeString(vout.ScriptPubKey.Hex)
	if err != nil {
		return nil, fmt.Errorf("cant hex decode utxos %v script", utxo)
	}

	sats_btc_amount, err := btcutil.NewAmount(vout.Value)
	if err != nil {
		return nil, err
	}

	sats_int64 := int64(sats_btc_amount)

	return &btcapi.UnspentOutput{
		Outpoint: wire.NewOutPoint(hash, n),
		Output:   wire.NewTxOut(sats_int64, script_bytes),
	}, nil
}

type unspentOutputWorkerResult struct {
	unspent *btcapi.UnspentOutput
	index   int
}

func getUnspentOutputWorker(network string, utxo string, index int, results chan<- unspentOutputWorkerResult) {
	attempts := 3
	var result *btcapi.UnspentOutput
	var err error
	for attempts > 0 {
		attempts--
		result, err = getUnspentOutput(network, utxo)
		if result != nil && err == nil {
			break
		}
		time.Sleep(time.Millisecond * 50)
	}
	results <- unspentOutputWorkerResult{unspent: result, index: index}
}

func getUnspentOutputList(network string, utxos []string) ([]*btcapi.UnspentOutput, error) {
	results_channel := make(chan unspentOutputWorkerResult, len(utxos))

	for i := 0; i < len(utxos); i++ {
		go getUnspentOutputWorker(network, utxos[i], i, results_channel)
	}

	results := make([]*btcapi.UnspentOutput, len(utxos))
	var err error
	for range utxos {
		worker_result := <-results_channel
		results[worker_result.index] = worker_result.unspent

		if results[worker_result.index] == nil {
			err = fmt.Errorf("cant get utxo info %v", utxos[worker_result.index])
		}
	}
	close(results_channel)

	if err != nil {
		return nil, err
	}

	return results, nil
}

func sendRawTransaction(network string, rawTx string) (string, error) {
	node, err := get_node(network)
	if err != nil {
		return "", fmt.Errorf("error getting RPC node: %v", err)
	}
	defer node.Shutdown()

	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return "", fmt.Errorf("error decoding raw transaction: %v", err)
	}

	msgTx := wire.NewMsgTx(wire.TxVersion)
	if err := msgTx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return "", fmt.Errorf("error deserializing transaction: %v", err)
	}

	txid, err := node.SendRawTransaction(msgTx, false)
	if err != nil {
		return "", fmt.Errorf("error sending transaction: %v", err)
	}

	return txid.String(), nil
}
