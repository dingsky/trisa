package sqlliteModel

import "time"

type TblTxnList struct {
	ID         string    `"gorm":"column:id"`
	Hash       string    `"gorm":"column:hash"`
	Currency   string    `"gorm":"column:currency"`
	Count      string    `"gorm":"column:count"`
	Amount     string    `"gorm":"column:amount"`
	Date       string    `"gorm":"column:date"`
	CreateTime time.Time `"gorm":"column:create_time"`
	UpdateTime time.Time `"gorm":"column:update_time"`
}
