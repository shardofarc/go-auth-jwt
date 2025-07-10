package initializers

import "github.com/shardofarc/go-auth-jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})

}
