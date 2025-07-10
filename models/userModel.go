package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UserGuid string `gorm:"unique"`
	Refresh  string
}
