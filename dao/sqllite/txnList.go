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

func (s *txnListCollection) UpdateByKeyRet(key string, txn *sqlliteModel.TblTxnList) error {
	return Database.Model(&sqlliteModel.TblTxnList{}).Where("key_ret = ?", key).Updates(txn).Error
}

func (s *txnListCollection) Select(id string) (*sqlliteModel.TblTxnList, error) {
	txn := new(sqlliteModel.TblTxnList)
	result := Database.Where("id = ?", id).First(txn)
	return txn, result.Error
}

func (s *txnListCollection) SelectAll() ([]*sqlliteModel.TblTxnList, error) {
	txnlist := make([]*sqlliteModel.TblTxnList, 0)
	result := Database.Find(&txnlist)
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
