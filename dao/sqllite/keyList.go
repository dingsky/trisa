package sqllite

import (
	"github.com/trisacrypto/trisa/model/sqlliteModel"
)

type kycListCollection struct {
}

var KycListCollectionCol = new(kycListCollection)

func (a *kycListCollection) Insert(serv *sqlliteModel.TblKycList) error {
	return Database.Create(serv).Error
}

func (a *kycListCollection) Delete(currency, address string) error {
	serv := new(sqlliteModel.TblKycList)
	return Database.Where("currency = ? and wallet_address = ?", currency, address).Delete(serv).Error
}

func (a *kycListCollection) Update(serv *sqlliteModel.TblKycList) error {
	return Database.Save(serv).Error
}

func (a *kycListCollection) Select(currency, address string) (*sqlliteModel.TblKycList, error) {
	serv := new(sqlliteModel.TblKycList)
	result := Database.Where("currency = ? and wallet_address = ?", currency, address).First(serv)
	return serv, result.Error
}

func (a *kycListCollection) SelectAll(id, name, kycType, currency, timeStart, timeEnd string) ([]*sqlliteModel.TblKycList, error) {
	serv := make([]*sqlliteModel.TblKycList, 0)

	query := new(sqlliteModel.TblKycList)
	query.KycId = id
	query.Name = name
	query.Type = kycType
	query.Currency = currency
	db := Database.Model(&sqlliteModel.TblKycList{}).Where(query)
	if timeStart != "" {
		db = db.Where("create_time >= ?", timeStart)
	}
	if timeEnd != "" {
		db = db.Where("create_time <= ?", timeEnd)
	}

	result := db.Order("create_time desc").Find(&serv)
	return serv, result.Error
}
