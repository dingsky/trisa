package sqlliteModel

type TblTxnList struct {
	CusId   string `"gorm":"column:cus_id" json:"cus_id,omitempty"`
	Name    string `"gorm":"column:name" json:"name,omitempty"`
	TxnTime string `"gorm":"column:txn_time" json:"txn_time,omitempty"`
	Type    string `"gorm":"column:type" json:"type,omitempty"`

	TxnID       string  `"gorm":"column:txn_id" json:"txn_id,omitempty"`
	Hash        string  `"gorm":"column:hash" json:"hash,omitempty"`
	Currency    string  `"gorm":"column:currency" json:"currency,omitempty"`
	Count       float64 `"gorm":"column:count" json:"count,omitempty"`
	Amount      float64 `"gorm":"column:amount" json:"amount,omitempty"`
	TotalAmount float64 `"gorm":"column:total_amount" json:"total_amount,omitempty"`
	Status      string  `"gorm":"column:status" json:"status,omitempty"`

	//	Net                   string    `"gorm":"column:net" json:"net,omitempty"`
	Date                  string `"gorm":"column:date" json:"date,omitempty"`
	SenderName            string `"gorm":"column:sender_name" json:"sender_name,omitempty"`
	SenderWalletAddress   string `"gorm":"column:sender_wallet_address" json:"sender_wallet_address,omitempty"`
	SenderAddress         string `"gorm":"column:sender_address" json:"sender_address,omitempty"`
	SenderId              string `"gorm":"column:sender_id" json:"sender_id,omitempty"`
	SenderDate            string `"gorm":"column:sender_date" json:"sender_date,omitempty"`
	SenderIdentifyInfo    string `"gorm":"column:sender_identify_info" json:"sender_identify_info,omitempty"`
	RecieverName          string `"gorm":"column:reciever_name" json:"reciever_name,omitempty"`
	RecieverWalletAddress string `"gorm":"column:reciever_wallet_address" json:"reciever_wallet_address,omitempty"`
	RecieverAddress       string `"gorm":"column:reciever_address" json:"reciever_address,omitempty"`
	RecieverId            string `"gorm":"column:reciever_id" json:"reciever_id,omitempty"`
	RecieverDate          string `"gorm":"column:reciever_date" json:"reciever_date,omitempty"`
	RecieverIdentifyInfo  string `"gorm":"column:reciever_identify_info" json:"reciever_identify_info,omitempty"`
	Key                   string `"gorm":"column:key" json:"key,omitempty"`
	KeyRet                string `"gorm":"column:key_ret" json:"key_ret,omitempty"`
	RecieverType          string `"gorm":"column:reciever_type" json:"reciever_type,omitempty"`
	RecieverCertificateID string `"gorm":"column:reciever_certificate_id" json:"reciever_certificate_id,omitempty"`
	SenderType            string `"gorm":"column:sender_type" json:"sender_type,omitempty"`
	SenderCertificateID   string `"gorm":"column:sender_certificate_id" json:"sender_certificate_id,omitempty"`
	ExamineStatus         string `"gorm":"column:examine_status" json:"examine_status,omitempty"`
	SeriNum               string `"gorm":"column:serial_number" json:"serial_number,omitempty"`
}
