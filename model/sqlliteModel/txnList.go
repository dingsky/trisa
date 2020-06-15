package sqlliteModel

import "time"

type TblTxnList struct {
	TxnID                 string    `"gorm":"column:txn_id" json:"txn_id,omitempty"`
	Hash                  string    `"gorm":"column:hash" json:"hash,omitempty"`
	Currency              string    `"gorm":"column:currency" json:"currency,omitempty"`
	Count                 int64     `"gorm":"column:count" json:"count,omitempty"`
	Amount                float64   `"gorm":"column:amount" json:"amount,omitempty"`
	Net                   string    `"gorm":"column:net" json:"net,omitempty"`
	Date                  string    `"gorm":"column:date" json:"date,omitempty"`
	SenderName            string    `"gorm":"column:sender_name" json:"sender_name,omitempty"`
	SenderWalletAddress   string    `"gorm":"column:sender_wallet_address" json:"sender_wallet_address,omitempty"`
	SenderAddress         string    `"gorm":"column:sender_address" json:"sender_address,omitempty"`
	SenderId              string    `"gorm":"column:sender_id" json:"sender_id,omitempty"`
	SenderDate            string    `"gorm":"column:sender_date" json:"sender_date,omitempty"`
	SenderIdentifyInfo    string    `"gorm":"column:sender_identify_info" json:"sender_identify_info,omitempty"`
	RecieverName          string    `"gorm":"column:reciever_name" json:"reciever_name,omitempty"`
	RecieverWalletAddress string    `"gorm":"column:reciever_wallet_address" json:"reciever_wallet_address,omitempty"`
	RecieverAddress       string    `"gorm":"column:reciever_address" json:"reciever_address,omitempty"`
	RecieverId            string    `"gorm":"column:reciever_id" json:"reciever_id,omitempty"`
	RecieverDate          string    `"gorm":"column:reciever_date" json:"reciever_date,omitempty"`
	RecieverIdentifyInfo  string    `"gorm":"column:reciever_identify_info" json:"reciever_identify_info,omitempty"`
	Key                   string    `"gorm":"column:key" json:"key,omitempty"`
	CreateTime            time.Time `"gorm":"column:create_time" json:"create_time,omitempty"`
	UpdateTime            time.Time `"gorm":"column:update_time" json:"update_time,omitempty"`
}
