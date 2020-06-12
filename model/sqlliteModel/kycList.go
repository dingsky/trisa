package sqlliteModel

import "time"

type TblKycList struct {
	Name          string    `"gorm":"column:name"`
	WalletAddress string    `"gorm":"column:wallet_address"`
	Address       string    `"gorm":"column:address"`
	KycId         string    `"gorm":"column:kyc_id"`
	Date          string    `"gorm":"column:date"`
	IdentifyInfo  string    `"gorm":"column:identify_info"`
	CreateTime    time.Time `"gorm":"column:create_time"`
	UpdateTime    time.Time `"gorm":"column:update_time"`
}
