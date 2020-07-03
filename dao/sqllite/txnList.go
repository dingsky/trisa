package sqllite

import (
	"database/sql"
	"fmt"

	"github.com/trisacrypto/trisa/model/sqlliteModel"
)

type txnListCollection struct {
}

var TxnListCollectionCol = new(txnListCollection)

func (s *txnListCollection) Insert(txn *sqlliteModel.TblTxnList) error {
	return Database.Create(txn).Error
}

func (s *txnListCollection) Delete(id string) error {
	txn := new(sqlliteModel.TblTxnList)
	return Database.Where("id = ?", id).Delete(txn).Error
}

func (s *txnListCollection) DeleteAll() error {
	serv := new(sqlliteModel.TblTxnList)
	return Database.Model(&sqlliteModel.TblTxnList{}).Delete(serv).Error
}

func (s *txnListCollection) Update(key string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("key = ?", key).Updates(txn).Error
}

func (s *txnListCollection) UpdateByHash(hash string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("hash = ?", hash).Updates(txn).Error
}

func (s *txnListCollection) UpdateTotalAmount(query *sqlliteModel.TblTxnList, totalAmount float64) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where(query).Update("total_amount", totalAmount).Error
}

func (s *txnListCollection) UpdateByKeyRet(key string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("key_ret = ?", key).Updates(txn).Error
}

func (s *txnListCollection) Select(id string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("id = ?", id).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectByIdCurType(id, currency, txnType string) (float64, error) {
	var total_amount []sql.NullFloat64
	fmt.Printf("cust_id:%s, currency:%s, txn_type:%s", id, currency, txnType)
	result := Database.Model(&sqlliteModel.TblTxnList{}).Where("cus_id = ? and currency = ? and type = ?", id, currency, txnType).Pluck("MAX(amount) as total_amount", &total_amount)
	if result.Error != nil {
		return 0, result.Error
	}
	fmt.Printf("total:%v", total_amount)
	return total_amount[0].Float64, nil
}

func (s *txnListCollection) SelectAll(query *sqlliteModel.TblTxnList, minAmount, maxAmount, minCount, maxCount, minTotalAmount, maxTotalAmount float64, startTime, endTime, estatus string) ([]*sqlliteModel.TblTxnList, error) {

	txnlist := make([]*sqlliteModel.TblTxnList, 0)
	db := Database.Model(&sqlliteModel.TblTxnList{}).Where(query)
	if minAmount > 0.00000000 {
		db = db.Where("amount >= ?", minAmount)
	}

	if maxAmount > 0.00000000 {
		db = db.Where("amount <= ?", maxAmount)
	}

	if minCount > 0.00000000 {
		db = db.Where("count >= ?", minCount)
	}

	if maxCount > 0.00000000 {
		db = db.Where("count <= ?", maxCount)
	}

	if minTotalAmount > 0.00000000 {
		db = db.Where("total_amount >= ?", minTotalAmount)
	}

	if maxTotalAmount > 0.00000000 {
		db = db.Where("total_amount <= ?", maxTotalAmount)
	}

	if estatus == "0" {
		db = db.Where("examine_status = ?", "todo")
		db = db.Where("type <> ?", "transaction")
	}

	if estatus == "1" {
		db = db.Where("examine_status = ? or examine_status = ?", "pass", "refuse")
	}

	if startTime != "" {
		db = db.Where("txn_time >= ?", startTime)
	}

	if endTime != "" {
		db = db.Where("txn_time <= ?", endTime)
	}

	db = db.Where("status <> ?", "notshow")

	result := db.Order("txn_time desc").Find(&txnlist)
	return txnlist, result.Error
}

func (s *txnListCollection) SelectByHash(hash string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("hash = ?", hash).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectByKey(key string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("key_ret = ?", key).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectBySeriNum(seriNum string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	fmt.Printf("serial_number:%s", seriNum)
	result := Database.Where("serial_number = ?", seriNum).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectByRetKey(key string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("key_ret = ?", key).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectKey(key string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("key = ?", key).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) UpdateByKeyHash(hash string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("hash = ?", hash).Updates(txn).Error
}
