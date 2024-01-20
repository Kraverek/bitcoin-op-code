package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"bitcoin-op-code/pkg/btcapi"
	"bitcoin-op-code/pkg/btcapi/mempoolApi"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"

	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	DefaultSequenceNum = wire.MaxTxInSequenceNum - 10
)

func handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error reading request body")
		return
	}

	var createWalletModel createWalletModel
	err = json.Unmarshal(body, &createWalletModel)
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	walletJSON, err := getNewWallet(createWalletModel.Network, createWalletModel.Seed)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(walletJSON))
}

func handleListUnspent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error reading request body")
		return
	}

	var listUnspentModel ListUnspentModel
	err = json.Unmarshal(body, &listUnspentModel)
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	if len(listUnspentModel.Address) <= 0 {
		writeResponseError(w, "no address")
		return
	}

	netParams := getNetParamsByString(listUnspentModel.Network)
	client := mempoolApi.NewClient(netParams)

	address, err := btcutil.DecodeAddress(listUnspentModel.Address, netParams) // Użyj chaincfg.TestNet3Params dla testnetu
	if err != nil {
		writeResponseError(w, fmt.Sprintf("Niepoprawny adres: %v", err))
		return
	}

	unspent_outputs, err := client.ListUnspent(address)
	if err != nil {
		writeResponseError(w, err.Error())
		return
	}

	results := make(map[string]interface{})

	for _, output := range unspent_outputs {
		txid := output.Outpoint.Hash.String()
		vout := output.Outpoint.Index
		value := output.Output.Value

		key := fmt.Sprintf("%s:%d", txid, vout)
		results[key] = value
	}

	responseJSON, err := json.Marshal(results)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("Błąd serializacji JSON: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(responseJSON)
}

func handleSendUtxos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error reading request body")
		return
	}

	var sendUtxosModel SendUtxosModel
	err = json.Unmarshal(body, &sendUtxosModel)
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	if len(sendUtxosModel.Utxos) <= 0 {
		writeResponseError(w, "no utxos")
		return
	}

	netParams := getNetParamsByString(sendUtxosModel.Network)

	var privateKeys []*btcec.PrivateKey

	if len(sendUtxosModel.PrivateKeys) > 0 {
		if len(sendUtxosModel.PrivateKeys) != len(sendUtxosModel.Utxos) {
			writeResponseError(w, fmt.Sprintf("len of private keys (%v) is != len of utxos (%v)", len(sendUtxosModel.PrivateKey), len(sendUtxosModel.Utxos)))
			return
		}

		for _, pk_bytes := range sendUtxosModel.PrivateKeys {
			privateKeyBytes, err := hex.DecodeString(pk_bytes)
			if err != nil {
				writeResponseError(w, "error on decoding private key")
				return
			}
			if len(privateKeyBytes) == 0 {
				writeResponseError(w, "no private_key")
				return
			}
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	} else if sendUtxosModel.PrivateKey != "" {
		privateKeyBytes, err := hex.DecodeString(sendUtxosModel.PrivateKey)
		if err != nil {
			writeResponseError(w, "error on decoding private key")
			return
		}
		if len(privateKeyBytes) == 0 {
			writeResponseError(w, "no private_key")
			return
		}
		for range sendUtxosModel.Utxos {
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	}
	if len(privateKeys) <= 0 {
		writeResponseError(w, "no private_keys")
		return
	}

	taprootKeyNoScript := txscript.ComputeTaprootKeyNoScript(privateKeys[0].PubKey())
	schnorr := schnorr.SerializePubKey(taprootKeyNoScript)
	taprootAddress, err := btcutil.NewAddressTaproot(schnorr, netParams)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("decoding taprootAddress err: %v", err))
		return
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)

	var unspent_outputs []*btcapi.UnspentOutput

	if sendUtxosModel.UseApi {
		unspent_outputs, err = getUnspentOutputs_mempool(sendUtxosModel.Network, sendUtxosModel.Utxos)
	} else {
		unspent_outputs, err = getUnspentOutputList(sendUtxosModel.Network, sendUtxosModel.Utxos)
	}

	utxos_value := int64(0)
	for i := range sendUtxosModel.Utxos {
		unspentOutput := unspent_outputs[i]
		prevOutputFetcher.AddPrevOut(*unspentOutput.Outpoint, unspentOutput.Output)
		in := wire.NewTxIn(unspentOutput.Outpoint, nil, nil)
		in.Sequence = DefaultSequenceNum
		tx.AddTxIn(in)
		utxos_value += unspentOutput.Output.Value
	}

	var transfered int64
	for _, destination := range sendUtxosModel.Destinations {
		destinationAddress, err := btcutil.DecodeAddress(destination.Address, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination address")
			return
		}

		destinationPkScript, err := txscript.PayToAddrScript(destinationAddress)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination PkScript")
			return
		}

		tx.AddTxOut(&wire.TxOut{
			PkScript: destinationPkScript,
			Value:    destination.Value,
		})
		transfered += destination.Value
	}

	var changePkScript []byte
	if sendUtxosModel.ChangeDestination == "" {
		changePkScript, err = txscript.PayToAddrScript(taprootAddress)
	} else {
		changeDestinationAddress, err := btcutil.DecodeAddress(sendUtxosModel.ChangeDestination, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding change address")
			return
		}
		changePkScript, err = txscript.PayToAddrScript(changeDestinationAddress)
	}

	if err != nil {
		writeResponseError(w, fmt.Sprintf("Problem with getting change address %v", err))
		return
	}

	tx.AddTxOut(&wire.TxOut{
		PkScript: changePkScript,
		Value:    0,
	})

	// do this twice so we get fee of signed tx and change fee in tx and sign again with good fee!
	var fee int64
	var change int64
	for i := 0; i < 2; i++ {
		fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosModel.FeeRate
		change = utxos_value - transfered - fee
		if change < 330 {
			tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
			err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
			if err != nil {
				writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
				return
			}
			fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosModel.FeeRate
			change = utxos_value - transfered - fee
			if change < 0 {
				writeResponseError(w, "insufficient balance")
				return
			} else if change > 0 {
				fee += change
				change = 0
			}

			break
		}
		if change >= 0 {
			tx.TxOut[len(tx.TxOut)-1].Value = change
		}

		err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
		if err != nil {
			writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
			return
		}
	}

	signed_tx, err := GetTxHex(tx)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("Error on getting signed tx hex: %v", err))
		return
	}

	sendUtxosOutput := SendUtxosOutput{
		SendTxHex:        signed_tx,
		Fee:              fee,
		Change:           change,
		TotalInputAmount: utxos_value,
		Transfered:       transfered,
	}

	writeResponseSendUtxos(w, &sendUtxosOutput)
}

func handleSendUtxosOpCat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error reading request body")
		return
	}

	var sendUtxosModel SendUtxosModel
	err = json.Unmarshal(body, &sendUtxosModel)
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	if len(sendUtxosModel.Utxos) <= 0 {
		writeResponseError(w, "no utxos")
		return
	}

	netParams := getNetParamsByString(sendUtxosModel.Network)

	var privateKeys []*btcec.PrivateKey

	if len(sendUtxosModel.PrivateKeys) > 0 {
		if len(sendUtxosModel.PrivateKeys) != len(sendUtxosModel.Utxos) {
			writeResponseError(w, fmt.Sprintf("len of private keys (%v) is != len of utxos (%v)", len(sendUtxosModel.PrivateKey), len(sendUtxosModel.Utxos)))
			return
		}

		for _, pk_bytes := range sendUtxosModel.PrivateKeys {
			privateKeyBytes, err := hex.DecodeString(pk_bytes)
			if err != nil {
				writeResponseError(w, "error on decoding private key")
				return
			}
			if len(privateKeyBytes) == 0 {
				writeResponseError(w, "no private_key")
				return
			}
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	} else if sendUtxosModel.PrivateKey != "" {
		privateKeyBytes, err := hex.DecodeString(sendUtxosModel.PrivateKey)
		if err != nil {
			writeResponseError(w, "error on decoding private key")
			return
		}
		if len(privateKeyBytes) == 0 {
			writeResponseError(w, "no private_key")
			return
		}
		for range sendUtxosModel.Utxos {
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	}
	if len(privateKeys) <= 0 {
		writeResponseError(w, "no private_keys")
		return
	}

	taprootKeyNoScript := txscript.ComputeTaprootKeyNoScript(privateKeys[0].PubKey())
	schnorr := schnorr.SerializePubKey(taprootKeyNoScript)
	taprootAddress, err := btcutil.NewAddressTaproot(schnorr, netParams)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("decoding taprootAddress err: %v", err))
		return
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)

	var unspent_outputs []*btcapi.UnspentOutput

	if sendUtxosModel.UseApi {
		unspent_outputs, err = getUnspentOutputs_mempool(sendUtxosModel.Network, sendUtxosModel.Utxos)
	} else {
		unspent_outputs, err = getUnspentOutputList(sendUtxosModel.Network, sendUtxosModel.Utxos)
	}

	utxos_value := int64(0)
	for i := range sendUtxosModel.Utxos {
		unspentOutput := unspent_outputs[i]
		prevOutputFetcher.AddPrevOut(*unspentOutput.Outpoint, unspentOutput.Output)
		in := wire.NewTxIn(unspentOutput.Outpoint, nil, nil)
		in.Sequence = DefaultSequenceNum
		tx.AddTxIn(in)
		utxos_value += unspentOutput.Output.Value
	}

	var transfered int64
	for _, destination := range sendUtxosModel.Destinations {
		destinationAddress, err := btcutil.DecodeAddress(destination.Address, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination address")
			return
		}

		destinationPkScript, err := txscript.PayToAddrScript(destinationAddress)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination PkScript")
			return
		}

		tx.AddTxOut(&wire.TxOut{
			PkScript: destinationPkScript,
			Value:    destination.Value,
		})
		transfered += destination.Value
	}

	var scriptOP_CATPk []byte
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_CAT)
	scriptOP_CATPk, err = builder.Script()

	tx.AddTxOut(&wire.TxOut{
		PkScript: scriptOP_CATPk,
		Value:    0,
	})

	var changePkScript []byte
	if sendUtxosModel.ChangeDestination == "" {
		changePkScript, err = txscript.PayToAddrScript(taprootAddress)
	} else {
		changeDestinationAddress, err := btcutil.DecodeAddress(sendUtxosModel.ChangeDestination, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding change address")
			return
		}
		changePkScript, err = txscript.PayToAddrScript(changeDestinationAddress)
	}

	if err != nil {
		writeResponseError(w, fmt.Sprintf("Problem with getting change address %v", err))
		return
	}

	tx.AddTxOut(&wire.TxOut{
		PkScript: changePkScript,
		Value:    0,
	})

	// do this twice so we get fee of signed tx and change fee in tx and sign again with good fee!
	var fee int64
	var change int64
	for i := 0; i < 2; i++ {
		fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosModel.FeeRate
		change = utxos_value - transfered - fee
		if change < 330 {
			tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
			err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
			if err != nil {
				writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
				return
			}
			fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosModel.FeeRate
			change = utxos_value - transfered - fee
			if change < 0 {
				writeResponseError(w, "insufficient balance")
				return
			} else if change > 0 {
				fee += change
				change = 0
			}

			break
		}
		if change >= 0 {
			tx.TxOut[len(tx.TxOut)-1].Value = change
		}

		err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
		if err != nil {
			writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
			return
		}
	}

	signed_tx, err := GetTxHex(tx)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("Error on getting signed tx hex: %v", err))
		return
	}

	sendUtxosOutput := SendUtxosOutput{
		SendTxHex:        signed_tx,
		Fee:              fee,
		Change:           change,
		TotalInputAmount: utxos_value,
		Transfered:       transfered,
	}

	writeResponseSendUtxos(w, &sendUtxosOutput)
}

func handleSendUtxosOpReturn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error reading request body")
		return
	}

	var sendUtxosOpReturnModel SendUtxosOpReturnModel
	err = json.Unmarshal(body, &sendUtxosOpReturnModel)
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	if len(sendUtxosOpReturnModel.Utxos) <= 0 {
		writeResponseError(w, "no utxos")
		return
	}

	netParams := getNetParamsByString(sendUtxosOpReturnModel.Network)

	var privateKeys []*btcec.PrivateKey

	if len(sendUtxosOpReturnModel.PrivateKeys) > 0 {
		if len(sendUtxosOpReturnModel.PrivateKeys) != len(sendUtxosOpReturnModel.Utxos) {
			writeResponseError(w, fmt.Sprintf("len of private keys (%v) is != len of utxos (%v)", len(sendUtxosOpReturnModel.PrivateKey), len(sendUtxosOpReturnModel.Utxos)))
			return
		}

		for _, pk_bytes := range sendUtxosOpReturnModel.PrivateKeys {
			privateKeyBytes, err := hex.DecodeString(pk_bytes)
			if err != nil {
				writeResponseError(w, "error on decoding private key")
				return
			}
			if len(privateKeyBytes) == 0 {
				writeResponseError(w, "no private_key")
				return
			}
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	} else if sendUtxosOpReturnModel.PrivateKey != "" {
		privateKeyBytes, err := hex.DecodeString(sendUtxosOpReturnModel.PrivateKey)
		if err != nil {
			writeResponseError(w, "error on decoding private key")
			return
		}
		if len(privateKeyBytes) == 0 {
			writeResponseError(w, "no private_key")
			return
		}
		for range sendUtxosOpReturnModel.Utxos {
			privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
			privateKeys = append(privateKeys, privateKey)
		}
	}
	if len(privateKeys) <= 0 {
		writeResponseError(w, "no private_keys")
		return
	}

	taprootKeyNoScript := txscript.ComputeTaprootKeyNoScript(privateKeys[0].PubKey())
	schnorr := schnorr.SerializePubKey(taprootKeyNoScript)
	taprootAddress, err := btcutil.NewAddressTaproot(schnorr, netParams)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("decoding taprootAddress err: %v", err))
		return
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	prevOutputFetcher := txscript.NewMultiPrevOutFetcher(nil)

	var unspent_outputs []*btcapi.UnspentOutput

	if sendUtxosOpReturnModel.UseApi {
		unspent_outputs, err = getUnspentOutputs_mempool(sendUtxosOpReturnModel.Network, sendUtxosOpReturnModel.Utxos)
	} else {
		unspent_outputs, err = getUnspentOutputList(sendUtxosOpReturnModel.Network, sendUtxosOpReturnModel.Utxos)
	}

	utxos_value := int64(0)
	for i := range sendUtxosOpReturnModel.Utxos {
		unspentOutput := unspent_outputs[i]
		prevOutputFetcher.AddPrevOut(*unspentOutput.Outpoint, unspentOutput.Output)
		in := wire.NewTxIn(unspentOutput.Outpoint, nil, nil)
		in.Sequence = DefaultSequenceNum
		tx.AddTxIn(in)
		utxos_value += unspentOutput.Output.Value
	}

	var transfered int64
	for _, destination := range sendUtxosOpReturnModel.Destinations {
		destinationAddress, err := btcutil.DecodeAddress(destination.Address, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination address")
			return
		}

		destinationPkScript, err := txscript.PayToAddrScript(destinationAddress)
		if err != nil {
			writeResponseError(w, "Problem with decoding Destination PkScript")
			return
		}

		tx.AddTxOut(&wire.TxOut{
			PkScript: destinationPkScript,
			Value:    destination.Value,
		})
		transfered += destination.Value
	}

	var opReturnPkScript []byte
	opReturnData := []byte(sendUtxosOpReturnModel.Message)
	opReturnPkScript, err = txscript.NullDataScript(opReturnData)

	tx.AddTxOut(&wire.TxOut{
		PkScript: opReturnPkScript,
		Value:    0,
	})

	var changePkScript []byte
	if sendUtxosOpReturnModel.ChangeDestination == "" {
		changePkScript, err = txscript.PayToAddrScript(taprootAddress)
	} else {
		changeDestinationAddress, err := btcutil.DecodeAddress(sendUtxosOpReturnModel.ChangeDestination, netParams)
		if err != nil {
			writeResponseError(w, "Problem with decoding change address")
			return
		}
		changePkScript, err = txscript.PayToAddrScript(changeDestinationAddress)
	}

	if err != nil {
		writeResponseError(w, fmt.Sprintf("Problem with getting change address %v", err))
		return
	}

	tx.AddTxOut(&wire.TxOut{
		PkScript: changePkScript,
		Value:    0,
	})

	// do this twice so we get fee of signed tx and change fee in tx and sign again with good fee!
	var fee int64
	var change int64
	for i := 0; i < 2; i++ {
		fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosOpReturnModel.FeeRate
		change = utxos_value - transfered - fee
		if change < 330 {
			tx.TxOut = tx.TxOut[:len(tx.TxOut)-1]
			err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
			if err != nil {
				writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
				return
			}
			fee = mempool.GetTxVirtualSize(btcutil.NewTx(tx)) * sendUtxosOpReturnModel.FeeRate
			change = utxos_value - transfered - fee
			if change < 0 {
				writeResponseError(w, "insufficient balance")
				return
			} else if change > 0 {
				fee += change
				change = 0
			}

			break
		}
		if change >= 0 {
			tx.TxOut[len(tx.TxOut)-1].Value = change
		}

		err = SignCommitTx(tx, privateKeys, prevOutputFetcher)
		if err != nil {
			writeResponseError(w, fmt.Sprintf("Error on signing tx: %v", err))
			return
		}
	}

	signed_tx, err := GetTxHex(tx)
	if err != nil {
		writeResponseError(w, fmt.Sprintf("Error on getting signed tx hex: %v", err))
		return
	}

	sendUtxosOutput := SendUtxosOutput{
		SendTxHex:        signed_tx,
		Fee:              fee,
		Change:           change,
		TotalInputAmount: utxos_value,
		Transfered:       transfered,
	}

	writeResponseSendUtxos(w, &sendUtxosOutput)
}

func handleSendRawTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeResponseError(w, "Invalid request method")
		return
	}

	var req RawTransactionRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	defer r.Body.Close()
	if err != nil {
		writeResponseError(w, "Error unmarshalling json")
		return
	}

	if len(req.TxHex) == 0 {
		writeResponseError(w, "No raw transaction provided")
		return
	}

	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		writeResponseError(w, "Error decoding hex string")
		return
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		writeResponseError(w, "Error deserializing transaction")
		return
	}

	netParams := getNetParamsByString(req.Network)
	client := mempoolApi.NewClient(netParams)
	txHash, err := client.BroadcastTx(&tx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Błąd podczas wysyłania transakcji: %v", err), http.StatusInternalServerError)
		return
	}

	response := fmt.Sprintf("{\"txid\": \"%s\"}", txHash.String())
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response))
}

func main() {
	http.HandleFunc("/create_wallet", handleCreateWallet)
	http.HandleFunc("/listunspent", handleListUnspent)
	http.HandleFunc("/send_utxos", handleSendUtxos)
	http.HandleFunc("/send_utxos_op_cat", handleSendUtxosOpCat)
	http.HandleFunc("/send_utxos_op_return", handleSendUtxosOpReturn)
	http.HandleFunc("/send_raw_transaction", handleSendRawTransaction)

	log.Fatal(http.ListenAndServe(":7777", nil))
}
