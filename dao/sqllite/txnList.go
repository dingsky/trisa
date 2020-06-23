package sqllite

import (
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

func (s *txnListCollection) Update(key string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("key = ?", key).Updates(txn).Error
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

func (s *txnListCollection) SelectAll(query *sqlliteModel.TblTxnList, minAmount, maxAmount, minCount, maxCount, minTotalAmount, maxTotalAmount float64, startTime, endTime string) ([]*sqlliteModel.TblTxnList, error) {

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

	if startTime != "" {
		db = db.Where("txn_time >= ?", startTime)
	}

	if endTime != "" {
		db = db.Where("txn_time <= ?", endTime)
	}

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
	result := Database.Where("key = ?", key).First(txn)
	return txn, result.Error
}
