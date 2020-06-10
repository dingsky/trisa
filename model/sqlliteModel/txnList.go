package sqlliteModel

import "time"

type TblTxnList struct {
	ID                    string    `"gorm":"column:id"`
	Hash                  string    `"gorm":"column:hash"`
	Currency              string    `"gorm":"column:currency"`
	Count                 int64     `"gorm":"column:count"`
	Amount                float64   `"gorm":"column:amount"`
	Date                  string    `"gorm":"column:date"`
	SenderName            string    `"gorm":"column:sender_name"`
	SenderWalletAddress   string    `"gorm":"column:sender_wallet_address"`
	SenderAddress         string    `"gorm":"column:sender_address"`
	SenderId              string    `"gorm":"column:sender_id"`
	SenderDate            string    `"gorm":"column:sender_date"`
	SenderIdentifyInfo    string    `"gorm":"column:sender_identify_info"`
	RecieverName          string    `"gorm":"column:reciever_name"`
	RecieverWalletAddress string    `"gorm":"column:reciever_wallet_address"`
	RecieverAddress       string    `"gorm":"column:reciever_address"`
	RecieverId            string    `"gorm":"column:reciever_id"`
	RecieverDate          string    `"gorm":"column:reciever_date"`
	RecieverIdentifyInfo  string    `"gorm":"column:reciever_identify_info"`
	CreateTime            time.Time `"gorm":"column:create_time"`
	UpdateTime            time.Time `"gorm":"column:update_time"`
}
