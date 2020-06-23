package sqlliteModel

type TblKycList struct {
	Currency      string `"gorm":"column:currency" json:"currency,omitempty"`
	Net           string `"gorm":"column:net" json:"net,omitempty"`
	Name          string `"gorm":"column:name" json:"name,omitempty"`
	WalletAddress string `"gorm":"column:wallet_address" json:"wallet_address,omitempty"`
	Address       string `"gorm":"column:address" json:"address,omitempty"`
	KycId         string `"gorm":"column:kyc_id" json:"kyc_id,omitempty"`
	Date          string `"gorm":"column:date" json:"date,omitempty"`
	IdentifyInfo  string `"gorm":"column:identify_info" json:"identify_info,omitempty"`
	Type          string `"gorm":"column:type" json:"type,omitempty"`
	CertificateID string `"gorm":"column:certificate_id" json:"certificate_id,omitempty"`
	CreateTime    string `"gorm":"column:create_time" json:"create_time,omitempty"`
	UpdateTime    string `"gorm":"column:update_time" json:"update_time,omitempty"`
}
