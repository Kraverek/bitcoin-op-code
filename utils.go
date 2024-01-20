package main

import (
	"bitcoin-op-code/pkg/btcapi"
	"bitcoin-op-code/pkg/btcapi/mempoolApi"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func GetTxHex(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func SignCommitTx(msgTx *wire.MsgTx, privateKeys []*btcec.PrivateKey, prevOutputFetcher *txscript.MultiPrevOutFetcher) error {
	if len(msgTx.TxIn) != len(privateKeys) {
		return errors.New(fmt.Sprintf("length of priv keys (%v) != len of commit tx inputs (%v)", len(privateKeys), len(msgTx.TxIn)))
	}

	witnessList := make([]wire.TxWitness, len(msgTx.TxIn))
	for i := range msgTx.TxIn {
		txOut := prevOutputFetcher.FetchPrevOutput(msgTx.TxIn[i].PreviousOutPoint)
		witness, err := txscript.TaprootWitnessSignature(
			msgTx, txscript.NewTxSigHashes(msgTx, prevOutputFetcher), i,
			txOut.Value, txOut.PkScript, txscript.SigHashDefault, privateKeys[i])
		if err != nil {
			return err
		}
		witnessList[i] = witness
	}
	for i := range witnessList {
		msgTx.TxIn[i].Witness = witnessList[i]
	}

	return nil
}

func getNetParamsByString(network string) *chaincfg.Params {
	if network == "testnet" {
		return &chaincfg.TestNet3Params
	}
	if network == "signet" {
		return &chaincfg.SigNetParams
	}
	if network == "regtest" {
		return &chaincfg.RegressionNetParams
	}
	return &chaincfg.MainNetParams
}

func getStrEnv(envName string, default_value ...string) string {
	myVar := os.Getenv(envName)
	if myVar == "" && len(default_value) > 0 {
		myVar = default_value[0]
	}
	return myVar
}

func getNewWallet(network string, seedHex string) (string, error) {
	var seed []byte
	var err error

	if seedHex != "" {
		seed, err = hex.DecodeString(seedHex)
		if err != nil {
			return "", err
		}
	} else {
		seed, err = hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		if err != nil {
			return "", err
		}
		seedHex = hex.EncodeToString(seed)
	}

	netParams := getNetParamsByString(network)

	masterKey, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		return "", err
	}

	childKey, err := masterKey.Derive(0)
	if err != nil {
		return "", err
	}

	pubKey, err := childKey.ECPubKey()
	if err != nil {
		return "", err
	}
	publicKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())

	witnessProg := btcutil.Hash160(pubKey.SerializeCompressed())
	segWitAddress, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, netParams)
	if err != nil {
		return "", err
	}

	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return "", err
	}

	taprootKeyNoScript := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())
	schnorr := schnorr.SerializePubKey(taprootKeyNoScript)
	taprootAddress, err := btcutil.NewAddressTaproot(schnorr, netParams)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyHex := hex.EncodeToString(privKey.Serialize())

	wif, err := btcutil.NewWIF(privKey, netParams, true)
	if err != nil {
		return "", err
	}

	wallet := WalletData{
		Seed:           seedHex,
		MasterKey:      masterKey.String(),
		ChildKey:       childKey.String(),
		PublicKeyHex:   publicKeyHex,
		SegWitAddress:  segWitAddress.EncodeAddress(),
		TaprootAddress: taprootAddress.String(),
		PrivateKeyWIF:  wif.String(),
		PrivateKeyHex:  privateKeyHex,
	}

	jsonData, err := json.Marshal(wallet)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func splitUtxoString(input string) (string, uint32, error) {
	parts := strings.SplitN(input, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("input does not contain a single ':' separator")
	}

	uintPart, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", 0, fmt.Errorf("second part is not an integer: %v", err)
	}

	return parts[0], uint32(uintPart), nil
}

func writeResponseSendUtxos(w http.ResponseWriter, sendUtxosOutput *SendUtxosOutput) {
	json_str, err := json.Marshal(ResponseSendUtxos{Result: sendUtxosOutput})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json_str)
}

func writeResponseError(w http.ResponseWriter, msg string) {
	json_str, err := json.Marshal(ResponseError{Error: &msg})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json_str)
}

func getUnspentOutputs_mempool(network string, utxos []string) ([]*btcapi.UnspentOutput, error) {
	netParams := getNetParamsByString(network)
	client := mempoolApi.NewClient(netParams)

	unspentOutputs := make([]*btcapi.UnspentOutput, 0, len(utxos))

	for _, utxo := range utxos {
		tx_hash, n, err := splitUtxoString(utxo)
		if err != nil {
			return nil, err
		}

		hash, err := chainhash.NewHashFromStr(tx_hash)
		if err != nil {
			return nil, err
		}

		tx, err := client.GetTransactionDetails(hash)
		if err != nil {
			return nil, err
		}

		if int(n) >= len(tx.Vout) {
			return nil, fmt.Errorf("wrong input number for utxo %v: tx has only %d outputs", utxo, len(tx.Vout))
		}

		vout := tx.Vout[n]

		script_bytes, err := hex.DecodeString(vout.Script)
		if err != nil {
			return nil, fmt.Errorf("can't hex decode utxo %v script: %v", utxo, err)
		}

		unspentOutput := &btcapi.UnspentOutput{
			Outpoint: wire.NewOutPoint(hash, uint32(n)),
			Output:   wire.NewTxOut(vout.Value, script_bytes),
		}

		unspentOutputs = append(unspentOutputs, unspentOutput)
	}

	return unspentOutputs, nil
}
