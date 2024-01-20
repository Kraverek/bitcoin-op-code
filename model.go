package main

type ResponseError struct {
	Error *string `json:"error"`
}

type createWalletModel struct {
	Network string `json:"network"`
	Seed    string `json:"seed"`
}

type DestinationModel struct {
	Address string `json:"address"`
	Value   int64  `json:"value"`
}

type RawTransactionRequest struct {
	TxHex   string `json:"send_tx_hex"`
	Network string `json:"network"`
}

type ListUnspentModel struct {
	Address string `json:"address"`
	Network string `json:"network"`
}

type SendUtxosModel struct {
	PrivateKey        string             `json:"private_key"`
	PrivateKeys       []string           `json:"private_keys"`
	Utxos             []string           `json:"utxos"`
	Destinations      []DestinationModel `json:"destinations"`
	ChangeDestination string             `json:"change_destination"`
	FeeRate           int64              `json:"fee_rate"`
	Network           string             `json:"network"`

	UseApi bool `json:"use_api"` // true: uses an external API, false: directly uses a Bitcoin node
}

type SendUtxosOutput struct {
	SendTxHex        string `json:"send_tx_hex"`
	Fee              int64  `json:"fee"`
	Change           int64  `json:"change"`
	TotalInputAmount int64  `json:"total_input_amount"`
	Transfered       int64  `json:"transfered"`
}

type ResponseSendUtxos struct {
	Result *SendUtxosOutput `json:"result"`
	Error  *string          `json:"error"`
}

type WalletData struct {
	Seed           string `json:"seed"`
	MasterKey      string `json:"master_key"`
	ChildKey       string `json:"child_key"`
	PublicKeyHex   string `json:"public_key_hex"`
	SegWitAddress  string `json:"segwit_address"`
	TaprootAddress string `json:"taproot_address"`
	PrivateKeyWIF  string `json:"private_key_wif"`
	PrivateKeyHex  string `json:"private_key_hex"`
}

type SendUtxosOpReturnModel struct {
	PrivateKey        string             `json:"private_key"`
	PrivateKeys       []string           `json:"private_keys"`
	Utxos             []string           `json:"utxos"`
	Destinations      []DestinationModel `json:"destinations"`
	ChangeDestination string             `json:"change_destination"`
	FeeRate           int64              `json:"fee_rate"`
	Network           string             `json:"network"`

	UseApi  bool   `json:"use_api"` // true: uses an external API, false: directly uses a Bitcoin node
	Message string `json:"message"`
}
