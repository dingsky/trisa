package sqllite

import (
	"os"

	"github.com/trisacrypto/trisa/model/sqlliteModel"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"gitlab.devops.wx/blockchains/baseutil/log"
)

const (
	dataBaseSqlLite = "sqlite3"
)

var Database *gorm.DB
var err error

func init() {
	// Connect to database
	Database, err = gorm.Open(dataBaseSqlLite, "./db")
	if err != nil {
		log.Errorf("open sqllite err:%s", err)
		os.Exit(1)
	}

	address := new(sqlliteModel.TblKycList)
	Database.AutoMigrate(address)

	serv := new(sqlliteModel.TblTxnList)
	Database.AutoMigrate(serv)
}
